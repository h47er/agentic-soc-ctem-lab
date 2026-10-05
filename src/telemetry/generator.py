#!/usr/bin/env python3
"""
Synthetic SOC Telemetry Generator — safe by design
===================================================
Produces attack-shaped alert data from templates. NO exploit code, NO real
attack traffic, NO offensive tooling — this exists so the triage pipeline and
detection-coverage engine can be exercised end-to-end without touching real
infrastructure.

Attack scenarios are modeled after MITRE ATT&CK enterprise techniques and
common real-world incident patterns (ransomware precursors, BEC, credential
stuffing, living-off-the-land).
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

random.seed(2026)  # reproducible datasets

USERS = ["m.asante", "j.mugisha", "a.byiringiro", "c.uwase", "d.ntaganda",
         "s.mukamana", "p.habimana", "e.kayitesi", "finance-bot", "svc-backup"]
HOSTS = ["WS-" + str(1000 + i) for i in range(40)] + \
        ["SRV-" + n for n in ("FILE01", "APP02", "SQL03")] + \
        ["DC-CORE01", "FIN-ERP01"]
IPS_EXTERNAL = ["45.33.32.156", "103.4.217.4", "185.220.101.7", "91.219.236.18"]
IPS_INTERNAL = ["10.0." + str(a) + "." + str(b) for a in range(1, 5) for b in range(2, 60)]

# --- benign alert templates (the daily noise floor) ------------------------
BENIGN = [
    {"source": "EDR", "rule_name": "Suspicious PowerShell - Encoding Detected",
     "severity": "MEDIUM", "attack": ["T1059.001"],
     "details": {"process": "powershell.exe", "note": "chocolatey package install"}},
    {"source": "IDS", "rule_name": "Outbound TLS to New Domain",
     "severity": "LOW", "attack": ["T1071.001"], "details": {}},
    {"source": "AUTH", "rule_name": "User Logged In Outside Normal Hours",
     "severity": "LOW", "attack": ["T1078"], "details": {}},
    {"source": "EDR", "rule_name": "Macro-Enabled Document Opened",
     "severity": "MEDIUM", "attack": ["T1204.002"],
     "details": {"process": "winword.exe"}},
    {"source": "CLOUD", "rule_name": "New OAuth Grant - Common App",
     "severity": "LOW", "attack": ["T1550.001"], "details": {}},
    {"source": "MAIL", "rule_name": "External Sender First Contact",
     "severity": "LOW", "attack": ["T1566.001"], "details": {}},
]

# --- attack scenario templates (multi-alert chains) -------------------------
SCENARIOS = {
    "ransomware_precursor": [
        {"source": "EDR", "rule_name": "Suspicious PowerShell - Encoded Payload",
         "severity": "HIGH", "attack": ["T1059.001", "TA0002"],
         "details": {"process": "powershell.exe", "cmd": "DownloadString pattern"}},
        {"source": "EDR", "rule_name": "Process Injected into lsass.exe",
         "severity": "CRITICAL", "attack": ["T1003.001", "TA0006"], "details": {}},
        {"source": "EDR", "rule_name": "Mass File Rename Detected",
         "severity": "CRITICAL", "attack": ["T1486", "TA0040"],
         "details": {"files_renamed": 14000}},
        {"source": "IDS", "rule_name": "Beacon-like C2 Traffic",
         "severity": "HIGH", "attack": ["T1071.001", "TA0011"], "details": {}},
    ],
    "credential_stuffing": [
        {"source": "AUTH", "rule_name": "Failed Logins Spike",
         "severity": "MEDIUM", "attack": ["T1110.003", "TA0006"],
         "details": {"failures": 340}},
        {"source": "AUTH", "rule_name": "Impossible Travel",
         "severity": "HIGH", "attack": ["T1078", "TA0001"],
         "details": {"identity_risk": 0.9}},
        {"source": "AUTH", "rule_name": "MFA Fatigue Push Storm",
         "severity": "HIGH", "attack": ["T1621", "TA0006"],
         "details": {"identity_risk": 0.85}},
    ],
    "bec_payment_fraud": [
        {"source": "MAIL", "rule_name": "Lookalike Domain Inbound",
         "severity": "HIGH", "attack": ["T1566.003", "TA0001"],
         "details": {"domain": "c0mpany-finance.com"}},
        {"source": "MAIL", "rule_name": "Wire Transfer Request - Executive Impersonation",
         "severity": "CRITICAL", "attack": ["T1534", "TA0001"],
         "details": {"amount_usd": 240000}},
    ],
    "living_off_the_land": [
        {"source": "EDR", "rule_name": "certutil.exe Download Activity",
         "severity": "HIGH", "attack": ["T1105", "TA0005"],
         "details": {"process": "certutil.exe"}},
        {"source": "EDR", "rule_name": "Scheduled Task Created by Script",
         "severity": "MEDIUM", "attack": ["T1053.005", "TA0004"],
         "details": {"process": "schtasks.exe"}},
        {"source": "EDR", "rule_name": "LSASS Handle Access via comsvcs.dll",
         "severity": "CRITICAL", "attack": ["T1003.001", "TA0006"], "details": {}},
    ],
}


def _host_for(kind: str) -> str:
    prefix = {"critical": "DC-", "high": "FIN-", "server": "SRV-", "workstation": "WS-"}
    pool = [h for h in HOSTS if h.startswith(prefix.get(kind, "WS-"))]
    return random.choice(pool) if pool else random.choice(HOSTS)


def generate(hours: float, attack_ratio: float, out: Path) -> None:
    now = time.time()
    start = now - hours * 3600
    alerts: list[dict] = []
    aid = 0

    # benign noise
    n_benign = int(hours * random.uniform(80, 140))
    for _ in range(n_benign):
        t = random.choice(BENIGN)
        alerts.append({
            "alert_id": f"ALT-{aid:06d}",
            "timestamp": round(random.uniform(start, now), 2),
            "source": t["source"],
            "rule_name": t["rule_name"],
            "severity_raw": t["severity"],
            "entity_user": random.choice(USERS),
            "entity_host": random.choice(HOSTS),
            "entity_ip": random.choice(IPS_INTERNAL),
            "mitre_attack": t["attack"],
            "details": dict(t["details"]),
        })
        aid += 1

    # attack chains
    n_scenarios = max(1, int(n_benign * attack_ratio / 3))
    for _ in range(n_scenarios):
        name = random.choice(list(SCENARIOS))
        chain = SCENARIOS[name]
        base_ts = random.uniform(start, now - len(chain) * 400)
        user = random.choice(USERS)
        kind = random.choice(["workstation", "workstation", "server", "high", "critical"])
        host = _host_for(kind)
        ext_ip = random.choice(IPS_EXTERNAL)
        for i, step in enumerate(chain):
            alerts.append({
                "alert_id": f"ALT-{aid:06d}",
                "timestamp": round(base_ts + i * random.uniform(120, 600), 2),
                "source": step["source"],
                "rule_name": step["rule_name"],
                "severity_raw": step["severity"],
                "entity_user": user,
                "entity_host": host,
                "entity_ip": ext_ip if step["source"] == "IDS" else random.choice(IPS_INTERNAL),
                "mitre_attack": step["attack"],
                "details": dict(step["details"]),
            })
            aid += 1

    alerts.sort(key=lambda a: a["timestamp"])
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

    print(f"Generated {len(alerts)} alerts over {hours}h "
          f"({n_scenarios} attack scenarios, attack_ratio~{attack_ratio:.0%}) -> {out}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Synthetic SOC telemetry generator")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--attack-ratio", type=float, default=0.05)
    ap.add_argument("--output", default="data/alerts.jsonl")
    args = ap.parse_args()
    generate(args.hours, args.attack_ratio, Path(args.output))


if __name__ == "__main__":
    main()
