# 🤖 Agentic SOC & Continuous Threat Exposure Management Lab

> **Research-grade reference implementation** of next-generation security operations:
> an AI-agent-driven SOC pipeline fused with Continuous Threat Exposure Management (CTEM),
> mapped end-to-end to MITRE ATT&CK.

**Why this matters:** modern SOCs drown — thousands of alerts/day, ~30% never investigated,
analyst burnout measured in months. Meanwhile exposure management stays point-in-time (annual
pentests, quarterly scans) while infrastructure changes daily. This lab demonstrates the fix:
**agents do the Tier-1 cognitive load; exposure management runs as a continuous loop; every
detection is code, versioned, and ATT&CK-mapped.**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLOSED-LOOP ARCHITECTURE                          │
│                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐      │
│   │  TELEMETRY   │───▶│   AGENTS     │───▶│  TRIAGE & RESPONSE   │      │
│   │  synthetic + │    │  Enrichment  │    │  severity · verdicts │      │
│   │  real-shaped │    │  Correlation │    │  playbooks           │      │
│   └──────────────┘    │  Triage      │    └──────────┬───────────┘      │
│          ▲            └──────┬───────┘               │                  │
│          │                   │                       ▼                  │
│   ┌──────┴───────────┐       ▼            ┌──────────────────────┐      │
│   │  CTEM ENGINE     │  ┌──────────┐     │  DETECTION-AS-CODE   │      │
│   │  discover→       │◀─│  KNOWLEDGE│    │  Sigma rules ·       │      │
│   │  prioritize→     │  │  ATT&CK   │◀────│  ATT&CK mapping ·    │      │
│   │  validate→       │  │  graph    │     │  gap analysis        │      │
│   │  report  (loop)  │  └──────────┘     └──────────────────────┘      │
│   └──────────────────┘                                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## The Four Research Pillars

| # | Pillar | What it demonstrates | Entry point |
|---|--------|---------------------|-------------|
| 1 | **Agentic Triage** | LLM-style reasoning agent pipeline (enrich → correlate → verdict) that reduces alert noise 10:1 with explainable decisions | [`src/agents/`](src/agents/) |
| 2 | **Detection-as-Code** | Sigma rules with ATT&CK mapping, CI-validated, with automated **coverage-gap analysis** against adversary TTPs | [`rules/sigma/`](rules/sigma/) · [`src/detection/`](src/detection/) |
| 3 | **CTEM Engine** | The 5-stage Gartner loop (Scope → Discover → Prioritize → Validate → Mobilize) as executable Python with risk scoring | [`src/ctem/`](src/ctem/) |
| 4 | **Evaluation & Metrics** | MTTD/MTTR measurement, false-positive rate tracking, coverage percentage — the numbers that prove the system works | [`reports/`](reports/) · [`docs/metrics.md`](docs/metrics.md) |

## Quick Start

```bash
pip install -r requirements.txt

# Generate synthetic SOC telemetry (safe — no real attack traffic, ever)
python src/telemetry/generator.py --hours 24 --attack-ratio 0.05

# Run the agentic triage pipeline
python src/agents/pipeline.py --input data/alerts.jsonl --output reports/triage.jsonl

# Run CTEM assessment cycle
python src/ctem/engine.py --config configs/ctem.yaml --output reports/ctem-report.json

# Validate detection rules + measure ATT&CK coverage
python src/detection/coverage.py --rules rules/sigma/ --report reports/coverage.json

# Launch dashboard
python src/dashboard.py  # → http://localhost:8501
```

## Repository Layout

```
agentic-soc-ctem-lab/
├── README.md                    ← you are here
├── docs/
│   ├── whitepaper.md            ← the research narrative: problem → design → results
│   ├── architecture.md          ← component deep-dives & data flows
│   └── metrics.md               ← KPI definitions & how to interpret them
├── src/
│   ├── agents/                  ← Pillar 1: enrichment, correlation, triage agent
│   ├── detection/               ← Pillar 2: rule validation & ATT&CK coverage engine
│   ├── ctem/                    ← Pillar 3: the continuous exposure loop
│   └── telemetry/               ← synthetic data generator (safe by design)
├── rules/sigma/                 ← versioned Sigma detections, ATT&CK-mapped
├── configs/                     ← scoring weights, asset inventory, agent policies
├── dashboards/                  ← SOC & CTEM views
├── reports/                     ← generated outputs (triage verdicts, coverage, CTEM)
├── tests/                       ← unit + integration tests (CI-enforced)
└── .github/workflows/           ← CI: rule validation, tests, coverage regression gate
```

## Safety & Ethics

- **Synthetic telemetry only.** The generator produces attack-shaped data from templates.
  No exploit code, no real C2, no offensive tooling. This is a *defensive* research lab.
- **All detections are public Sigma rules** mapped to ATT&CK — nothing proprietary or weaponizable.
- **Agent decisions are explainable** — every verdict ships with its reasoning trail, because
  autonomous security tooling without auditability is a liability, not an asset.

## Related Work

Built on concepts from: Gartner CTEM (2022+), MITRE ATT&CK & D3FEND, Sigma HQ detections,
the SOC automation literature, and production lessons from operating a real SOC.

---
*Part of [h47er's](https://github.com/h47er) security research portfolio — African-built,
community-driven: each one, teach one.*
