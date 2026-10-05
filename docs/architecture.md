# Architecture Deep-Dive

## Data flow

```
alerts.jsonl ─▶ EnrichmentAgent ─▶ TriageAgent ─▶ verdicts (JSONL/report)
                     │                                ▲
                     ▼                                │
              CorrelationAgent ── incident candidates ─┘
                                              │
   rules/sigma/*.yml ─▶ coverage.py ──────────┼──▶ coverage.json (gaps feed detection backlog)
                                              │
   inventory+findings ─▶ ctem/engine.py ──────┘──▶ ctem-report.json ─▶ tasks (mobilized)
```

Every stage reads JSON in / writes JSON out — components are replaceable in isolation.

## Component contracts

### EnrichmentAgent
Input: `Alert` → Output: context dict. Keys (all optional, agents tolerate absence):
`asset_criticality` (1-5), `ti_verdict` (malicious/suspicious/unknown),
`rule_frequency`, `is_noisy_rule`, `trusted_process`, `identity_risk` (0-1).

### TriageAgent scoring backend
```python
def backend(alert: Alert, ctx: dict) -> list[tuple[str, float, str]]:
    """Return [(signal_name, weight_delta, human_explanation), ...]"""
```
Swap `_heuristic_backend` for any callable — e.g. a local model guarded by:
- structured output validation (reject non-conforming verdicts),
- mandatory reasoning trail (no trail → no verdict),
- sanity bounds (weights clamped to ±50).

### CTEM risk function
```
likelihood = 0.30·(CVSS/10) + 0.35·EPSS + 0.20·KEV + 0.15·exploit_available
impact     = 0.60·(criticality/5) + 0.25·data_sensitivity + 0.15·exposure
risk       = 100·(0.6·likelihood + 0.4·impact)   [×1.25 if internet-facing & KEV]
```
All weights live in plain constants / config — tune to your org's risk appetite and
document why. The weights encode a philosophy: *exploitation-in-practice beats theory*.

## Extending

- **New alert source** → add a template in `telemetry/generator.py`, an enrichment key in
  `EnrichmentAgent`, optionally a signal in the triage backend.
- **New detection** → drop a tagged Sigma YAML in `rules/sigma/`; coverage re-computes in CI.
- **New asset/finding** → extend `configs/ctem.yaml`; the loop re-scores automatically.
