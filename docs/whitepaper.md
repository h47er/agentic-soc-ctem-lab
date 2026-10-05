# Agentic SOC & Continuous Threat Exposure Management
### A Reference Implementation of New-Age Security Operations

**Author:** h47er · **Status:** Research publication · **Version:** 1.0 (October 2026)

---

## Abstract

Security Operations Centers face a structural, not technical, crisis: alert volumes grow
faster than analyst hiring, exposure management remains point-in-time while attack surface
changes continuously, and detection quality is asserted rather than measured. This paper
presents a working reference implementation that addresses all three through an integrated
architecture: **autonomous triage agents** for Tier-1 cognitive load, **detection-as-code**
with measured MITRE ATT&CK coverage, and an executable **Continuous Threat Exposure
Management (CTEM)** loop. We describe the design decisions, the explainability constraints
for autonomous decisions, and demonstrate the system on 2,197 synthetic alerts with
34 multi-stage attack chains, achieving a 25:1 noise-suppression ratio with fully
explainable verdicts.

## 1. Problem Statement

### 1.1 The triage death spiral
A mid-size SOC receives thousands of alerts daily. Industry telemetry consistently shows
a large share are never investigated; analysts burn out on false positives while real
multi-stage attacks sit in queues. The core failure is *cognitive*: every alert demands
enrichment (is this asset important? is this IP known-bad?) and context (what else happened
to this identity today?) before a human can judge it — and humans apply that context
inconsistently at volume.

### 1.2 Exposure management is not continuous
Annual pentests and monthly scans answer "what was exposed when we looked?" Attack surface
changes daily: new assets, new CVEs, KEV-listed vulnerabilities exploited within hours of
disclosure. The gap between *scan time* and *attack time* is where modern breaches live.

### 1.3 Detection quality is unmeasured
Most SOCs cannot answer "what percentage of relevant adversary TTPs can we actually see?"
Rules accumulate; coverage is assumed. Without measurement, detection engineering has no
backlog priority and no trend line.

## 2. Architecture

### 2.1 Agentic triage (Pillar 1)

Three cooperating agents replace Tier-1 manual triage:

- **EnrichmentAgent** — attaches asset criticality, threat-intel verdicts, rule-frequency
  (noise) statistics, process trust, and identity risk to every alert.
- **CorrelationAgent** — links alerts sharing an entity within a time window into incident
  candidates, extracting kill-chain progression from ATT&CK tactic ordering.
- **TriageAgent** — emits BENIGN / SUSPICIOUS / MALICIOUS verdicts with severity,
  confidence, and risk score. Critically, **the scoring backend is pluggable**: the
  reference implementation ships deterministic heuristics, but the same interface accepts
  a local model or guarded LLM without changing the pipeline contract.

**Design decision — explainability is a hard constraint.** Every verdict carries a
reasoning trail: named signals with weights. An autonomous system that suppresses alerts
without auditability is a liability; an SOC cannot defend "the AI decided" to a regulator
or an incident post-mortem. Our contract: *no verdict without a traceable why*.

### 2.2 Detection-as-code with measured coverage (Pillar 2)

Detections are Sigma rules in version control with ATT&CK technique tags. The coverage
engine validates rules, computes priority-technique coverage, and — the novel step —
cross-references coverage against **techniques observed in our own telemetry**, producing
a triaged gap backlog: "attacked here, blind there" outranks generic coverage gaps.
Coverage percentage is a CI-tracked metric that regresses visibly when rules break.

### 2.3 CTEM as an executable loop (Pillar 3)

The five Gartner stages become code:

| Stage | Implementation |
|---|---|
| Scope | Business-critical asset filter (criticality ≥ 3) |
| Discover | Asset-finding join across inventory |
| Prioritize | Risk = 0.6·likelihood + 0.4·impact, where likelihood blends CVSS (30%), EPSS (35%), KEV (20%), public exploit (15%) |
| Validate | Attack-path plausibility: exposure + exploitability + crown-jewel proximity |
| Mobilize | Priority-routed tasks (P1/P2/P3, due SLAs, owner teams) |

**Design decision — KEV dominance.** "Known exploited in the wild" contributes 20% of
likelihood and multiplies the final score for internet-facing assets. A KEV-listed VPN RCE
correctly outranks a higher-CVSS internal finding nobody is exploiting — the empirical
distribution of real-world exploitation, not theoretical severity, drives the math.

## 3. Results (synthetic evaluation)

On a 24-hour synthetic dataset (2,197 alerts, 34 multi-stage attack chains at ~5% attack
ratio — deliberately realistic noise levels):

| Metric | Result |
|---|---|
| Noise suppression ratio | **24.97 : 1** (2,197 alerts → 88 requiring human eyes) |
| Benign auto-closed | 96.0% |
| Incident candidates correlated | 28 (reconstructing the 34 injected chains with entity/time noise) |
| ATT&CK priority coverage (initial rule set) | 17.9% → **measured, now improvable** |
| Detection rate on own telemetry | 35.7% → gap backlog auto-generated (9 prioritized recommendations) |
| CTEM: validated exploitable paths | 3 of 6 findings; 1 P1 task (KEV VPN RCE) auto-mobilized |

The headline is not the specific numbers — it is that **these numbers exist**. The system
measures its own suppression ratio, coverage, and exposure rate on every cycle, making
improvement demonstrable rather than claimed.

## 4. Limitations & Future Work

1. **Synthetic-only evaluation.** Real telemetry shifts distributions; the pluggable
   scoring backend exists precisely to accommodate production-tuned models.
2. **Heuristic correlation.** Entity/time bucketing is a baseline; graph-based correlation
   (identity ↔ host ↔ process ↔ network as nodes) is the natural next step.
3. **LLM integration is deliberately not default.** A guarded local LLM backend
   (structured output, reasoning-trail requirement, hallucination checks) is the planned
   Pillar 1 upgrade; autonomy without the audit contract is unsafe.
4. **Validation stage is plausibility, not exploitation.** True validation requires a
   controlled attack-surface emulation environment (out of scope; keep the lab defensive).

## 5. Conclusion

The "new age" of security operations is not a tool — it is an architecture where agents
carry cognitive load under explainability constraints, detections are code with measured
coverage, and exposure management runs as a loop with mobilized output. This lab
demonstrates each pillar as working, tested, CI-gated code. The distance between this
reference and a production SOC is organizational, not conceptual.

## References

1. Gartner, *"How to Manage Cybersecurity Threats with Continuous Threat Exposure Management"*
2. MITRE ATT&CK Enterprise Matrix — attack.mitre.org
3. Sigma — Generic Signature Format for SIEM Systems — github.com/SigmaHQ
4. FIRST EPSS — Exploit Prediction Scoring System — first.org/epss
5. CISA Known Exploited Vulnerabilities Catalog — cisa.gov/kev
