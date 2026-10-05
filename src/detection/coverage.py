#!/usr/bin/env python3
"""
Detection-as-Code Coverage Engine — Pillar 2
=============================================
Validates Sigma rules, maps them to MITRE ATT&CK, and produces a
**coverage-gap analysis**: which adversary TTPs can we see, which are we
blind to, and which blind spots matter most given the techniques observed
in our own telemetry.

This is the measurable answer to "how good are our detections?" — a number
that trends in CI instead of a gut feeling.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# Techniques our synthetic telemetry exercises (from generator scenarios)
TELEMETRY_TECHNIQUES = {
    "T1059.001", "T1003.001", "T1486", "T1071.001", "T1110.003", "T1078",
    "T1621", "T1566.003", "T1534", "T1105", "T1053.005", "T1204.002",
    "T1550.001", "T1566.001",
}

# Techniques that matter for generic enterprise coverage (subset of ATT&CK)
PRIORITY_TECHNIQUES = {
    # initial access
    "T1566.001", "T1566.002", "T1566.003", "T1190", "T1078",
    # execution & persistence
    "T1059.001", "T1059.003", "T1053.005", "T1204.002", "T1547.001",
    # privilege escalation & defense evasion
    "T1055", "T1548.002", "T1105", "T1070.004",
    # credential access
    "T1003.001", "T1003.003", "T1110.003", "T1621",
    # discovery & lateral movement
    "T1087", "T1046", "T1021.001", "T1021.002",
    # collection, c2, exfiltration, impact
    "T1071.001", "T1071.004", "T1560.001", "T1041", "T1486", "T1530",
}

TACTIC_OF = {
    "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
    "T1059": "Execution", "T1053": "Execution", "T1204": "Execution",
    "T1055": "Privilege Escalation", "T1548": "Privilege Escalation",
    "T1070": "Defense Evasion", "T1105": "Command and Control",
    "T1003": "Credential Access", "T1110": "Credential Access", "T1621": "Credential Access",
    "T1087": "Discovery", "T1046": "Discovery",
    "T1021": "Lateral Movement",
    "T1071": "Command and Control", "T1560": "Collection",
    "T1041": "Exfiltration", "T1486": "Impact", "T1530": "Collection",
    "T1550": "Defense Evasion", "T1534": "Initial Access",
}


def parse_sigma(path: Path) -> dict | None:
    """Minimal Sigma YAML frontmatter parser without external deps."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m_title = re.search(r"^title:\s*(.+)$", text, re.M)
    m_level = re.search(r"^level:\s*(\w+)", text, re.M)
    m_status = re.search(r"^status:\s*(\w+)", text, re.M)
    tags = re.findall(r"attack\.([tT]\d{4}(?:\.\d{3})?)", text)
    tactics = re.findall(r"attack\.([a-z_]+)\b", text)
    if not m_title:
        return None
    return {
        "file": path.name,
        "title": m_title.group(1).strip(),
        "level": (m_level.group(1).lower() if m_level else "unknown"),
        "status": (m_status.group(1).lower() if m_status else "unknown"),
        "techniques": sorted({t.upper() for t in tags}),
        "tactics": sorted(set(tactics)),
    }


def load_rules(rules_dir: Path) -> list[dict]:
    rules = []
    for p in sorted(rules_dir.glob("*.y*ml")):
        r = parse_sigma(p)
        if r:
            rules.append(r)
        else:
            print(f"  ⚠️  invalid/unparseable rule skipped: {p.name}")
    return rules


def analyse(rules: list[dict], telemetry_techniques: set[str]) -> dict:
    covered = {t for r in rules for t in r["techniques"]}
    priority = set(PRIORITY_TECHNIQUES)
    gaps = priority - covered
    seen_gaps = telemetry_techniques & gaps          # attacked AND undetected
    covered_by_telemetry = telemetry_techniques & covered

    by_tactic: dict[str, dict] = {}
    for t in priority:
        tactic = next((v for k, v in TACTIC_OF.items() if t.startswith(k)), "Other")
        slot = by_tactic.setdefault(tactic, {"covered": [], "gaps": []})
        (slot["covered"] if t in covered else slot["gaps"]).append(t)

    return {
        "rules_loaded": len(rules),
        "rules_with_attack_mapping": sum(1 for r in rules if r["techniques"]),
        "coverage": {
            "priority_techniques_total": len(priority),
            "covered": len(priority & covered),
            "gaps": len(gaps),
            "coverage_pct": round(100 * len(priority & covered) / len(priority), 1),
        },
        "telemetry_alignment": {
            "techniques_in_telemetry": len(telemetry_techniques),
            "detected": sorted(covered_by_telemetry),
            "undetected_in_telemetry": sorted(seen_gaps),
            "detection_rate_on_telemetry": round(
                100 * len(covered_by_telemetry) / max(1, len(telemetry_techniques)), 1),
        },
        "by_tactic": by_tactic,
        "gap_recommendations": _recommend(seen_gaps, gaps),
    }


def _recommend(seen_gaps: set[str], all_gaps: set[str]) -> list[str]:
    recs = []
    for t in sorted(seen_gaps):
        recs.append(f"🔴 URGENT — technique {t} appears in our own attack telemetry but has "
                    f"no detection rule. Write a Sigma rule first (real-world exposure).")
    if "T1486" in all_gaps:
        recs.append("🟠 High — no ransomware (file-encryption impact) detection mapped. "
                    "Add mass-rename/entropy analytics.")
    if "T1003.003" in all_gaps:
        recs.append("🟠 High — no NTDS.dit dumping detection. Critical for domain compromise.")
    if len(all_gaps) > len(seen_gaps):
        recs.append(f"🟡 {len(all_gaps) - len(seen_gaps)} additional priority gaps without observed "
                    f"telemetry — schedule into detection engineering backlog by kill-chain stage.")
    return recs


def main() -> None:
    ap = argparse.ArgumentParser(description="Detection coverage & ATT&CK gap analysis")
    ap.add_argument("--rules", default="rules/sigma")
    ap.add_argument("--report", default="reports/coverage.json")
    args = ap.parse_args()

    rules = load_rules(Path(args.rules))
    print(f"Loaded {len(rules)} Sigma rules")
    analysis = analyse(rules, TELEMETRY_TECHNIQUES)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(analysis, indent=2), encoding="utf-8")

    c, t = analysis["coverage"], analysis["telemetry_alignment"]
    print(f"ATT&CK priority coverage: {c['coverage_pct']}% "
          f"({c['covered']}/{c['priority_techniques_total']})")
    print(f"Detection rate on own telemetry: {t['detection_rate_on_telemetry']}% "
          f"({len(t['detected'])}/{t['techniques_in_telemetry']})")
    for r in analysis["gap_recommendations"]:
        print(f"  {r}".encode("ascii", "replace").decode())
    print(f"Report -> {out}")


if __name__ == "__main__":
    main()
