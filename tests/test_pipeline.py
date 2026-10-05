"""Unit + integration tests for the Agentic SOC & CTEM lab."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agents.pipeline import Alert, TriagePipeline, load_config          # noqa: E402
from ctem.engine import CTEMEngine, Finding, Asset, compute_risk        # noqa: E402
from detection.coverage import analyse, PRIORITY_TECHNIQUES             # noqa: E402


def _alert(**kw):
    base = dict(alert_id="T1", timestamp=time.time(), source="EDR",
                rule_name="Test Rule", severity_raw="HIGH")
    base.update(kw)
    return Alert(**base)


# ---------------- agents ----------------

def test_benign_alert_stays_benign():
    p = TriagePipeline(load_config(None))
    a = _alert(rule_name="Outbound TLS to New Domain", severity_raw="LOW",
               entity_host="WS-1001", details={"process": "chrome.exe"})
    v = p.triager.triage(a, p.enricher.enrich(a))
    assert v.classification == "BENIGN"
    assert v.risk_score < 30
    assert v.reasoning  # explainability trail always present


def test_malicious_with_ti_and_kev_context_scores_high():
    p = TriagePipeline(load_config(None))
    a = _alert(severity_raw="CRITICAL", entity_host="DC-CORE01",
               entity_ip="45.33.32.156")  # malicious TI in default config
    v = p.triager.triage(a, p.enricher.enrich(a))
    assert v.classification in ("SUSPICIOUS", "MALICIOUS")
    assert v.risk_score >= 60
    signals = {r["signal"] for r in v.reasoning}
    assert "threat_intel" in signals  # TI verdict contributed
    assert v.classification == "MALICIOUS" and v.risk_score == 80.0


def test_correlation_links_chain():
    now = time.time()
    chain = [_alert(alert_id=f"T{i}", timestamp=now + i * 120,
                    entity_user="m.asante",
                    mitre_attack=["TA0002", "TA0006"])
             for i in range(3)]
    incidents = TriagePipeline(load_config(None)).correlator.correlate(chain)
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 3
    assert incidents[0].kill_chain_progression == ["TA0002", "TA0006"]


def test_no_correlation_across_entities():
    now = time.time()
    alerts = [_alert(alert_id="A", timestamp=now, entity_user="alice"),
              _alert(alert_id="B", timestamp=now + 60, entity_user="bob")]
    incidents = TriagePipeline(load_config(None)).correlator.correlate(alerts)
    assert incidents == []


# ---------------- ctem ----------------

def test_kev_internet_facing_beats_internal_low_epss():
    vpn = Asset("A1", "VPN-GW01", "server", "IT", 4, internet_facing=True,
                data_classification="confidential")
    ws = Asset("A2", "WS-1042", "workstation", "HR", 2, data_classification="internal")
    f = Finding("F1", "A1", "cve", "X", cvss=8.0, epss=0.5, kev_listed=True,
                exploit_available=True)
    f_kev = Finding("F1", "A1", "cve", "X", cvss=8.0, epss=0.5, kev_listed=True,
                    exploit_available=True)
    f_local = Finding("F2", "A2", "cve", "Y", cvss=8.0, epss=0.5)
    r_kev = compute_risk(f_kev, vpn)
    r_local = compute_risk(f_local, ws)
    assert r_kev > r_local


def test_ctem_full_cycle_runs_and_mobilizes():
    report = CTEMEngine({
        "risk_appetite": 55,
        "assets": [{"asset_id": "A1", "hostname": "VPN-GW01", "type": "server",
                    "business_unit": "IT", "criticality": 4, "internet_facing": True,
                    "data_classification": "confidential"}],
        "findings": [{"finding_id": "F1", "asset_id": "A1", "category": "cve",
                      "title": "VPN RCE", "cvss": 9.8, "epss": 0.9,
                      "kev_listed": True, "exploit_available": True}],
    }).run_cycle()
    assert report["stages"]["mobilize"]["tasks_created"] >= 1
    assert report["kpis"]["kev_unpatched"] == 1
    t = report["tasks"][0]
    assert t["priority"] == "P1" and t["due_days"] == 2 and t["owner_team"]


# ---------------- detection coverage ----------------

def test_coverage_gap_analysis_flags_undetected():
    rules = [{"file": "r.yml", "title": "R", "level": "high", "status": "stable",
              "techniques": ["T1003.001"], "tactics": ["credential_access"]}]
    telemetry = {"T1003.001", "T1486"}   # T1486 attacked but undetected
    a = analyse(rules, telemetry)
    assert "T1486" in a["telemetry_alignment"]["undetected_in_telemetry"]
    assert any("T1486" in r for r in a["gap_recommendations"])
    assert a["coverage"]["coverage_pct"] > 0


def run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
