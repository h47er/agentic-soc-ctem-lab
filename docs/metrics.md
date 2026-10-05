# Metrics & KPI Definitions

The numbers that prove the system works — with exact definitions so trends are honest.

## SOC efficiency

| Metric | Definition | Where computed |
|---|---|---|
| **Noise suppression ratio** | total alerts ÷ (SUSPICIOUS + MALICIOUS verdicts). Higher = agents absorb more Tier-1 load. | `pipeline.py` → `metrics.suppression_ratio` |
| **Benign auto-close %** | BENIGN verdicts ÷ total. The share never needing human eyes. | `metrics.benign_pct` |
| **Correlation yield** | incident candidates ÷ attack chains injected (synthetic) or ÷ confirmed incidents (real). | manual / dashboards |
| **MTTD** | attack-chain first-alert timestamp → first SUSPICIOUS+ verdict timestamp. | compare telemetry vs triage output |
| **MTTR** | mobilized task creation → closure (tracked in Case/CTEM systems). | task timestamps |

**Target trajectory:** suppression ≥ 20:1 with false-suppression rate (real attacks marked
BENIGN) < 1%. A rising suppression ratio *with* a rising false-suppression rate is worse,
not better — track both.

## Detection engineering

| Metric | Definition | Where computed |
|---|---|---|
| **Priority ATT&CK coverage** | covered priority techniques ÷ 28 priority techniques. The headline detection number. | `coverage.json` → `coverage.coverage_pct` |
| **Telemetry detection rate** | detected techniques ÷ techniques observed in own telemetry. "Can we see what actually attacks us?" | `telemetry_alignment.detection_rate_on_telemetry` |
| **Urgent gap count** | techniques in own telemetry with no rule. Should trend to **0**. | `gap_recommendations` (🔴 entries) |

Coverage is CI-gated (`.coverage-baseline`) — it can only rise deliberately.

## Exposure management

| Metric | Definition | Where computed |
|---|---|---|
| **Exposure rate** | findings above risk appetite ÷ total findings. | `ctem-report.json` → `kpis.exposure_rate` |
| **Validated exposure rate** | confirmed-exploitable findings ÷ total. The number executives should care about. | `kpis.validated_exposure_rate` |
| **KEV unpatched** | KEV-listed findings above appetite. Target: **0, always**. | `kpis.kev_unpatched` |
| **Mobilization SLA hit %** | P1 tasks closed ≤ 2 days ÷ P1 tasks created. Measures the MOBILIZE stage, not just scoring. | task timestamps |

## Reading the numbers together

- High suppression + low telemetry detection rate = the agents efficiently close noise but
  you're blind where it matters → fund detection engineering.
- High coverage % + high validated exposure = you *detect* attacks well but *exposure* is
  unmanaged → fund CTEM remediation capacity.
- All metrics green + no mobilized tasks closed = measurement theater → check SLA hit %.
