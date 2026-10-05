#!/usr/bin/env python3
"""
Agentic Triage Pipeline — Pillar 1
===================================
Alert processing pipeline with three cooperating agents:

  1. EnrichmentAgent  — attaches context: asset criticality, threat intel verdicts,
                        historical frequency, identity risk
  2. CorrelationAgent — links related alerts into incident candidates (time-bucket,
                        shared entity, kill-chain progression)
  3. TriageAgent      — produces verdicts: BENIGN / SUSPICIOUS / MALICIOUS with
                        severity, confidence, and a full explainability trail

Design principle: agents are *deterministic reasoning engines with pluggable
intelligence*. The `reason` method is rule/heuristic based in this reference
implementation, but the interface accepts any scoring backend (local model,
LLM with guardrails, external service) without changing the pipeline contract.

Every verdict is explainable: decisions trace to named signals with weights.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    alert_id: str
    timestamp: float
    source: str                    # EDR / IDS / mail-gateway / cloud / auth
    rule_name: str
    severity_raw: str              # as emitted by the source tool
    entity_user: str | None = None
    entity_host: str | None = None
    entity_ip: str | None = None
    mitre_attack: list[str] = field(default_factory=list)  # technique IDs
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

@dataclass
class Verdict:
    alert_id: str
    classification: str            # BENIGN / SUSPICIOUS / MALICIOUS
    severity: str                  # LOW / MEDIUM / HIGH / CRITICAL
    confidence: float              # 0..1
    risk_score: float              # 0..100
    reasoning: list[dict] = field(default_factory=list)

    def explain(self, signal: str, weight: float, detail: str) -> None:
        self.reasoning.append({"signal": signal, "weight": weight, "detail": detail})

@dataclass
class IncidentCandidate:
    """A cluster of related alerts the CorrelationAgent links together."""
    incident_id: str
    alerts: list[Alert]
    linked_by: list[str]           # correlation signals used
    kill_chain_progression: list[str]  # ordered ATT&CK tactics observed

# ---------------------------------------------------------------------------
# Pillar 1a — EnrichmentAgent
# ---------------------------------------------------------------------------

class EnrichmentAgent:
    """Attaches decision-relevant context to each alert."""

    def __init__(self, config: dict):
        self.asset_criticality: dict[str, int] = config.get("asset_criticality", {})
        self.threat_intel: dict[str, str] = config.get("threat_intel", {})  # ip → verdict
        self.alert_frequency: dict[str, int] = defaultdict(int)             # rule → count
        self.trusted_processes: set[str] = set(config.get("trusted_processes", []))

    def enrich(self, alert: Alert) -> dict[str, Any]:
        self.alert_frequency[alert.rule_name] += 1
        ctx: dict[str, Any] = {}

        host = alert.entity_host or ""
        ctx["asset_criticality"] = self.asset_criticality.get(host, 1)  # 1..5

        ip = alert.entity_ip or ""
        ctx["ti_verdict"] = self.threat_intel.get(ip, "unknown")

        ctx["rule_frequency"] = self.alert_frequency[alert.rule_name]
        ctx["is_noisy_rule"] = self.alert_frequency[alert.rule_name] > 50

        proc = str(alert.details.get("process", "")).lower()
        ctx["trusted_process"] = proc in self.trusted_processes if proc else None

        ctx["identity_risk"] = alert.details.get("identity_risk", 0)  # 0..1 optional
        return ctx

# ---------------------------------------------------------------------------
# Pillar 1b — CorrelationAgent
# ---------------------------------------------------------------------------

TACTIC_ORDER = [
    "TA0043", "TA0001",  # recon, initial access
    "TA0002", "TA0003", "TA0004", "TA0005",  # execution, persistence, priv-esc, defense-evas
    "TA0006", "TA0007", "TA0008", "TA0009",  # cred access, discovery, lateral, collection
    "TA0010", "TA0011",  # exfiltration, c2
    "TA0040",            # impact
]

class CorrelationAgent:
    """Groups alerts into incident candidates using shared entities + time windows."""

    def __init__(self, window_seconds: int = 3600):
        self.window = window_seconds

    def correlate(self, alerts: list[Alert]) -> list[IncidentCandidate]:
        # Bucket by shared entity (user or host), then link within time window
        by_entity: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            key = f"user:{a.entity_user}" if a.entity_user else f"host:{a.entity_host or a.entity_ip}"
            by_entity[key].append(a)

        incidents: list[IncidentCandidate] = []
        for key, group in sorted(by_entity.items()):
            group.sort(key=lambda a: a.timestamp)
            cluster: list[Alert] = []
            for a in group:
                if cluster and a.timestamp - cluster[-1].timestamp > self.window:
                    if len(cluster) >= 2:
                        incidents.append(self._build(key, cluster))
                    cluster = []
                cluster.append(a)
            if len(cluster) >= 2:
                incidents.append(self._build(key, cluster))
        return incidents

    def _build(self, entity: str, cluster: list[Alert]) -> IncidentCandidate:
        techniques = [t for a in cluster for t in a.mitre_attack]
        tactic_ids = {t.split(".")[0] for t in techniques if t.startswith("TA")}
        tactics = sorted(tactic_ids, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        return IncidentCandidate(
            incident_id=f"INC-{int(cluster[0].timestamp)}-{entity.split(':')[1]}",
            alerts=cluster,
            linked_by=[f"shared entity {entity}", "time window"],
            kill_chain_progression=tactics,
        )

# ---------------------------------------------------------------------------
# Pillar 1c — TriageAgent
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}
CRITICALITY_MULTIPLIER = {1: 1.0, 2: 1.15, 3: 1.3, 4: 1.6, 5: 2.0}

class TriageAgent:
    """
    Verdict engine with pluggable scoring backend.

    backend: optional callable(alert, enrichment) -> (score_delta, explanation)
             In production this is where a local LLM or remote model plugs in.
             The reference backend below is fully deterministic heuristics.
    """

    def __init__(self, config: dict, backend: Callable | None = None):
        self.weights = config.get("triage_weights", {})
        self.backend = backend or self._heuristic_backend

    # ---- reference heuristic backend (deterministic, explainable) ----
    def _heuristic_backend(self, alert: Alert, ctx: dict) -> list[tuple[str, float, str]]:
        signals: list[tuple[str, float, str]] = []
        base = SEVERITY_WEIGHTS.get(alert.severity_raw.upper(), 10)
        signals.append(("base_severity", base, f"source severity {alert.severity_raw}"))

        mult = CRITICALITY_MULTIPLIER.get(ctx.get("asset_criticality", 1), 1.0)
        if mult > 1.0:
            signals.append(("asset_criticality", base * (mult - 1),
                            f"asset criticality {ctx['asset_criticality']}/5"))

        if ctx.get("ti_verdict") == "malicious":
            signals.append(("threat_intel", 35, "source IP known-malicious in TI feed"))
        elif ctx.get("ti_verdict") == "suspicious":
            signals.append(("threat_intel", 15, "source IP flagged suspicious in TI feed"))

        if ctx.get("is_noisy_rule"):
            signals.append(("noise_penalty", -12,
                            f"rule fired {ctx['rule_frequency']}x in window — likely benign pattern"))

        if ctx.get("trusted_process"):
            signals.append(("trust_penalty", -15, "process is on the trusted allowlist"))

        n_tactics = len({t.split('.')[0] for t in alert.mitre_attack})
        if n_tactics >= 2:
            signals.append(("multi_stage", 12, f"alert spans {n_tactics} ATT&CK tactics"))

        if ctx.get("identity_risk", 0) > 0.7:
            signals.append(("identity_risk", 20, "high-risk identity signals (impossible travel / MFA fatigue)"))

        return signals

    def triage(self, alert: Alert, ctx: dict) -> Verdict:
        v = Verdict(alert_id=alert.alert_id, classification="BENIGN",
                    severity="LOW", confidence=0.0, risk_score=0.0)
        total = 0.0
        for signal, weight, detail in self.backend(alert, ctx):
            total += weight
            v.explain(signal, weight, detail)

        v.risk_score = max(0.0, min(100.0, total))
        v.classification = ("MALICIOUS" if v.risk_score >= 65 else
                            "SUSPICIOUS" if v.risk_score >= 30 else "BENIGN")
        v.severity = ("CRITICAL" if v.risk_score >= 80 else
                      "HIGH" if v.risk_score >= 65 else
                      "MEDIUM" if v.risk_score >= 30 else "LOW")
        # Confidence grows with the number of independent corroborating signals
        n = len(v.reasoning)
        v.confidence = round(min(0.95, 0.4 + 0.08 * n), 2)
        return v

# ---------------------------------------------------------------------------
# Pipeline assembly
# ---------------------------------------------------------------------------

class TriagePipeline:
    def __init__(self, config: dict):
        self.enricher = EnrichmentAgent(config)
        self.correlator = CorrelationAgent(config.get("correlation_window", 3600))
        self.triager = TriageAgent(config)

    def run(self, alerts: list[Alert]) -> dict:
        enriched = [(a, self.enricher.enrich(a)) for a in alerts]
        verdicts = [self.triager.triage(a, ctx) for a, ctx in enriched]
        incidents = self.correlator.correlate(
            [a for a, _ in enriched if self._needs_correlation(a, verdicts)]
        )
        return {
            "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_alerts": len(alerts),
            "verdicts": [asdict(v) for v in verdicts],
            "incident_candidates": [asdict(i) for i in incidents],
            "metrics": self._metrics(verdicts),
        }

    @staticmethod
    def _needs_correlation(alert: Alert, verdicts: list[Verdict]) -> bool:
        return alert.severity_raw.upper() in ("HIGH", "CRITICAL") or next(
            (v.classification != "BENIGN" for v in verdicts if v.alert_id == alert.alert_id), False)

    @staticmethod
    def _metrics(verdicts: list[Verdict]) -> dict:
        n = len(verdicts) or 1
        by_class = defaultdict(int)
        for v in verdicts:
            by_class[v.classification] += 1
        return {
            "suppression_ratio": round(n / max(1, by_class["MALICIOUS"] + by_class["SUSPICIOUS"]), 2),
            "benign_pct": round(100 * by_class["BENIGN"] / n, 1),
            "suspicious": by_class["SUSPICIOUS"],
            "malicious": by_class["MALICIOUS"],
        }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_config(path: str | None) -> dict:
    if path and Path(path).exists():
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "asset_criticality": {"WS-": 1, "SRV-": 3, "DC-": 5, "FIN-": 4},
        "threat_intel": {"45.33.32.156": "malicious", "103.4.217.4": "suspicious"},
        "trusted_processes": ["chrome.exe", "code.exe", "explorer.exe"],
        "correlation_window": 3600,
    }

def main() -> None:
    ap = argparse.ArgumentParser(description="Agentic SOC triage pipeline")
    ap.add_argument("--input", required=True, help="alerts JSONL file")
    ap.add_argument("--output", default="reports/triage.jsonl")
    ap.add_argument("--config", default=None, help="pipeline config JSON")
    args = ap.parse_args()

    alerts = [Alert.from_dict(json.loads(line)) for line in
              Path(args.input).read_text(encoding="utf-8").splitlines() if line.strip()]
    pipeline = TriagePipeline(load_config(args.config))
    result = pipeline.run(alerts)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    m = result["metrics"]
    print(f"Processed {result['total_alerts']} alerts")
    print(f"  benign: {m['benign_pct']}%  suspicious: {m['suspicious']}  malicious: {m['malicious']}")
    print(f"  noise suppression ratio: {m['suppression_ratio']}:1")
    print(f"  incident candidates: {len(result['incident_candidates'])}")
    print(f"Verdicts written -> {out}")

if __name__ == "__main__":
    main()
