#!/usr/bin/env python3
"""
CTEM Engine — Pillar 3
=======================
Continuous Threat Exposure Management as an executable loop, following the
five Gartner stages:

  1. SCOPE      — what matters? (business-critical assets from inventory)
  2. DISCOVER   — what exists & what's exposed? (assets, CVEs, misconfigs)
  3. PRIORITIZE — what should we fix first? (risk = likelihood × impact)
  4. VALIDATE   — can it actually be exploited? (attack-path validation)
  5. MOBILIZE   — does the right team act? (task generation & tracking)

The loop re-runs continuously (cron/CI); each cycle emits a delta report so
trend lines (exposure going up or down over time) become a first-class metric.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class Asset:
    asset_id: str
    hostname: str
    type: str                       # server / workstation / container / saas
    business_unit: str
    criticality: int                # 1..5 (5 = revenue/regulatory critical)
    internet_facing: bool = False
    data_classification: str = "internal"   # internal / confidential / restricted

@dataclass
class Finding:
    finding_id: str
    asset_id: str
    category: str                   # cve / misconfig / patch / cert / identity
    title: str
    cvss: float = 0.0
    epss: float = 0.0               # exploit probability 0..1 (FIRST EPSS-style)
    kev_listed: bool = False        # CISA Known Exploited Vulnerabilities
    exploit_available: bool = False
    compensating_control: str | None = None

@dataclass
class ExposureTask:
    """MOBILIZE output — a work item routed to the owning team."""
    task_id: str
    finding_id: str
    asset_id: str
    action: str
    owner_team: str
    priority: str
    due_days: int
    rationale: str

# ---------------------------------------------------------------------------
# Risk scoring — the heart of PRIORITIZE
# ---------------------------------------------------------------------------

def compute_risk(f: Finding, a: Asset) -> float:
    """
    Risk (0..100) blends exploitability signals with business impact:

      likelihood = CVSS (30%) + EPSS (35%) + KEV flag (20%) + exploit PoC (15%)
      impact     = asset criticality (60%) + data classification (25%) + exposure (15%)

    KEV dominates likelihood because "known exploited in the wild" beats any
    theoretical score. Internet-facing multiplies impact.
    """
    likelihood = (0.30 * (f.cvss / 10) + 0.35 * f.epss +
                  0.20 * (1.0 if f.kev_listed else 0.0) +
                  0.15 * (1.0 if f.exploit_available else 0.0))

    data_w = {"internal": 0.4, "confidential": 0.7, "restricted": 1.0}
    impact = (0.60 * (a.criticality / 5) + 0.25 * data_w.get(a.data_classification, 0.4) +
              0.15 * (1.0 if a.internet_facing else 0.0))

    risk = 100 * (0.6 * likelihood + 0.4 * impact)
    if a.internet_facing and f.kev_listed:
        risk = min(100.0, risk * 1.25)   # exposed + actively exploited = urgent
    if f.compensating_control and f.compensating_control.lower() == "waf":
        risk *= 0.85                      # virtual patching reduces but doesn't erase
    return round(risk, 1)

# ---------------------------------------------------------------------------
# The five stages
# ---------------------------------------------------------------------------

class CTEMEngine:
    def __init__(self, config: dict):
        self.assets = [Asset(**a) for a in config.get("assets", [])]
        self.findings = [Finding(**f) for f in config.get("findings", [])]
        self.risk_appetite = config.get("risk_appetite", 60)  # alert threshold

    # 1. SCOPE
    def scope(self) -> list[Asset]:
        return sorted((a for a in self.assets if a.criticality >= 3),
                      key=lambda a: -a.criticality)

    # 2. DISCOVER
    def discover(self) -> list[tuple[Finding, Asset]]:
        asset_map = {a.asset_id: a for a in self.assets}
        pairs = []
        for f in self.findings:
            a = asset_map.get(f.asset_id)
            if a:
                pairs.append((f, a))
        return pairs

    # 3. PRIORITIZE
    def prioritize(self, pairs: list[tuple[Finding, Asset]]) -> list[dict]:
        scored = [{"finding": f, "asset": a, "risk": compute_risk(f, a)} for f, a in pairs]
        return sorted(scored, key=lambda x: -x["risk"])

    # 4. VALIDATE — attack-path plausibility (heuristic reference impl)
    def validate(self, scored: list[dict]) -> None:
        for s in scored:
            f, a = s["finding"], s["asset"]
            chain = []
            if a.internet_facing:
                chain.append("internet-exposed entry point")
            if f.exploit_available or f.kev_listed:
                chain.append("public exploit path")
            if a.criticality >= 4:
                chain.append("direct path to crown-jewel data")
            s["attack_path"] = " -> ".join(chain) if chain else "no obvious path"
            s["validated_exploitable"] = len(chain) >= 2

    # 5. MOBILIZE
    def mobilize(self, scored: list[dict]) -> list[ExposureTask]:
        tasks = []
        for i, s in enumerate(scored):
            if s["risk"] < self.risk_appetite and not s.get("validated_exploitable"):
                continue
            f, a = s["finding"], s["asset"]
            days = 2 if s["risk"] >= 85 else 7 if s["risk"] >= 70 else 30
            priority = ("P1" if s["risk"] >= 85 else "P2" if s["risk"] >= 70 else "P3")
            tasks.append(ExposureTask(
                task_id=f"EXP-{i:04d}",
                finding_id=f.finding_id,
                asset_id=a.asset_id,
                action=self._action_for(f),
                owner_team=self._owner_for(f, a),
                priority=priority,
                due_days=days,
                rationale=(f"risk {s['risk']} | {s['attack_path']} | "
                           f"{'KEV-exploited' if f.kev_listed else 'per policy'}"),
            ))
        return tasks

    @staticmethod
    def _action_for(f: Finding) -> str:
        return {
            "cve": f"Patch: {f.title}",
            "misconfig": f"Remediate config: {f.title}",
            "patch": f"Deploy update: {f.title}",
            "cert": f"Replace certificate: {f.title}",
            "identity": f"Contain identity risk: {f.title}",
        }.get(f.category, f"Review: {f.title}")

    @staticmethod
    def _owner_for(f: Finding, a: Asset) -> str:
        if f.category == "identity":
            return "IAM Team"
        if a.type in ("container", "saas"):
            return "Platform Team"
        if a.criticality >= 4:
            return "Infra + App Owner (joint)"
        return "IT Operations"

    # ---- full cycle ----
    def run_cycle(self) -> dict:
        scoped = self.scope()
        pairs = self.discover()
        scored = self.prioritize(pairs)
        self.validate(scored)
        tasks = self.mobilize(scored)

        above = [s for s in scored if s["risk"] >= self.risk_appetite]
        return {
            "cycle_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "risk_appetite": self.risk_appetite,
            "stages": {
                "scope": {"in_scope_assets": len(scoped),
                          "top_assets": [a.hostname for a in scoped[:5]]},
                "discover": {"total_findings": len(self.findings),
                             "assets_with_findings": len({f.asset_id for f, _ in pairs})},
                "prioritize": {
                    "mean_risk": round(sum(s["risk"] for s in scored) / max(1, len(scored)), 1),
                    "above_appetite": len(above),
                    "top_exposures": [
                        {"finding": s["finding"].title, "asset": s["asset"].hostname,
                         "risk": s["risk"], "kev": s["finding"].kev_listed,
                         "attack_path": s.get("attack_path")}
                        for s in scored[:10]],
                },
                "validate": {"validated_exploitable":
                             sum(1 for s in scored if s.get("validated_exploitable"))},
                "mobilize": {"tasks_created": len(tasks),
                             "p1": sum(1 for t in tasks if t.priority == "P1")},
            },
            "tasks": [asdict(t) for t in tasks],
            "kpis": {
                "exposure_rate": round(100 * len(above) / max(1, len(scored)), 1),
                "kev_unpatched": sum(1 for s in scored if s["finding"].kev_listed
                                     and s["risk"] >= self.risk_appetite),
                "validated_exposure_rate": round(100 * sum(1 for s in scored if s.get("validated_exploitable"))
                                                 / max(1, len(scored)), 1),
            },
        }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "risk_appetite": 55,
    "assets": [
        {"asset_id": "A1", "hostname": "DC-CORE01", "type": "server", "business_unit": "IT",
         "criticality": 5, "internet_facing": False, "data_classification": "restricted"},
        {"asset_id": "A2", "hostname": "FIN-ERP01", "type": "server", "business_unit": "Finance",
         "criticality": 5, "internet_facing": False, "data_classification": "restricted"},
        {"asset_id": "A3", "hostname": "VPN-GW01", "type": "server", "business_unit": "IT",
         "criticality": 4, "internet_facing": True, "data_classification": "confidential"},
        {"asset_id": "A4", "hostname": "SRV-FILE01", "type": "server", "business_unit": "IT",
         "criticality": 3, "internet_facing": False, "data_classification": "confidential"},
        {"asset_id": "A5", "hostname": "WS-1042", "type": "workstation", "business_unit": "HR",
         "criticality": 2, "internet_facing": False, "data_classification": "restricted"},
    ],
    "findings": [
        {"finding_id": "F1", "asset_id": "A3", "category": "cve",
         "title": "CVE-2024-21762 VPN RCE", "cvss": 9.8, "epss": 0.94,
         "kev_listed": True, "exploit_available": True},
        {"finding_id": "F2", "asset_id": "A1", "category": "misconfig",
         "title": "SMBv1 enabled on domain controller", "cvss": 8.1, "epss": 0.55,
         "kev_listed": False, "exploit_available": True},
        {"finding_id": "F3", "asset_id": "A2", "category": "patch",
         "title": "ERP suite 14 months behind patch level", "cvss": 7.5, "epss": 0.3,
         "kev_listed": False, "exploit_available": False},
        {"finding_id": "F4", "asset_id": "A3", "category": "identity",
         "title": "VPN without MFA for legacy group", "cvss": 8.8, "epss": 0.7,
         "kev_listed": False, "exploit_available": True},
        {"finding_id": "F5", "asset_id": "A4", "category": "cert",
         "title": "TLS certificate expired 12 days ago", "cvss": 5.0, "epss": 0.05},
        {"finding_id": "F6", "asset_id": "A5", "category": "cve",
         "title": "Local privilege escalation CVE", "cvss": 7.8, "epss": 0.2,
         "compensating_control": "EDR"},
    ],
}

def main() -> None:
    ap = argparse.ArgumentParser(description="CTEM continuous exposure engine")
    ap.add_argument("--config", default=None, help="CTEM config JSON")
    ap.add_argument("--output", default="reports/ctem-report.json")
    args = ap.parse_args()

    config = DEFAULT_CONFIG
    if args.config and Path(args.config).exists():
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))

    report = CTEMEngine(config).run_cycle()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    s, k = report["stages"], report["kpis"]
    print(f"CTEM cycle -> {out}")
    print(f"  Scope:    {s['scope']['in_scope_assets']} critical assets in scope")
    print(f"  Discover: {s['discover']['total_findings']} findings")
    print(f"  Prioritize: mean risk {s['prioritize']['mean_risk']}, "
          f"{s['prioritize']['above_appetite']} above appetite")
    print(f"  Validate: {s['validate']['validated_exploitable']} confirmed exploitable paths")
    print(f"  Mobilize: {s['mobilize']['tasks_created']} tasks ({s['mobilize']['p1']} P1)")
    print(f"  KPIs: exposure {k['exposure_rate']}% | KEV unpatched {k['kev_unpatched']} "
          f"| validated-exposure {k['validated_exposure_rate']}%")

if __name__ == "__main__":
    main()
