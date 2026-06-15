# AEGIS KPI / Benchmark Harness

Single source of truth for **what to expect from AEGIS** and how to measure it
reproducibly. Replaces the former ad-hoc load-test runbook: the attack scenarios,
the KPI definitions, and the SLO targets all live here and in code.

Two levels:

| Level | Command | Needs the Pi? | Measures |
|---|---|---|---|
| **1 — deterministic** | `make benchmark-ci` | no | report structure/action/severity, UEBA gate, connector — on a labeled corpus with a fake model |
| **2 — live** | `make benchmark` | yes (stack + Pi) | latency, throughput, resources, semantic report quality under real attacks |

## Level 1 — `make benchmark-ci`

Runs `tests/benchmarks/` (pytest marker `benchmark`, excluded from the default
suite) against the labeled corpus `tests/fixtures/corpus/`, driving the pipeline
with a fake Ollama replaying *canonical* responses. It measures the
**deterministic** behaviour around the model and writes
`docs/benchmarks/kpi-ci-latest.json` (git-ignored):

- report quality: escalation, JSON validity, **action specificity** (the
  `recommended_action` carries the real IP/endpoint via the playbook), severity
  calibration vs the labeled floor;
- UEBA gate decision matrix (fail-open, FP discard, level/tier bypass);
- identity connector (sync success, idempotence, LDAP-failure fallback).

## Level 2 — `make benchmark` (and the scenario matrix)

`scripts/benchmark/scenarios.py` is the **single source of truth** for attack
scenarios, scaled by `--intensity {smoke,standard,soak}` (`soak` = parallel
loops, the high-volume "beaucoup de logs" test):

| Id | Scenario | Generation | Expected rules |
|---|---|---|---|
| A | Recon / scan | curl 404 sweep + `nikto` (if present) | 31151, 31108 |
| B | SQL injection | curl UNION/boolean/drop | 31103, 31152 |
| C | XSS | curl `<script>` / `onerror` | 31105, 31154 |
| D | Path traversal / LFI | curl `..%c0%af..`, `/etc/passwd` | 31153, 31104 |
| E | Command injection | curl `;id`, `|whoami` | 31103 |
| F | Brute force | `hydra` HTTP login (if present) | 31151 |
| G | High-sev mid-run | run B during a soak backlog | per B |
| H | Sustained soak | all scenarios, parallel, looped | all |
| I | Benign noise | netstat / dockerd promiscuous (host) | 533, 80710 (filtered) |

> The high-value custom rules (J: 100001-100042) can't be triggered from Kali
> against Juice Shop — they are covered as a **synthetic labeled corpus** at
> Level 1. Degraded/resilience cases (K) are covered at Level 1 (poison) and by
> injection during Level 2.

Run:

```bash
make benchmark SCENARIO=all INTENSITY=standard     # or INTENSITY=soak for load
# or step by step:
python -m scripts.benchmark.run_attack_suite --scenario B --intensity smoke
python -m scripts.benchmark.collect_kpis --since <T0> --until <T1>
```

`collect_kpis.py` queries Prometheus (PromQL from ADR 002 + `promql.py`) and
parses the middleware logs, writing `docs/benchmarks/report-<ts>.md` (+ `.json`,
both git-ignored). **Pi resource KPIs** (CPU/RAM/temperature) require a
`node_exporter` on the Pi scraped by Prometheus (`10.0.0.1:9100`); the Wazuh
agent CPU comes from the Wazuh API.

## SLO targets — acceptable thresholds and rationale

Provisional; the first representative live run sets the real baseline. "Why this
number" matters as much as the number.

| KPI | Acceptable threshold | Rationale | Source |
|---|---|---|---|
| **Attack recall** (real attacks escalated) | **≥ 95 %** | missing a real attack is the worst failure; aim 100 % on the corpus | Level-1 |
| **False-positive rate** (benign alert → LLM report) | **≤ 5 %** | each FP burns one ~5-9 min LLM cycle; human-in-the-loop tolerates a little, the Pi budget does not | Level-1 (benign corpus) / live |
| MTTT (triage) p95 | **< 90 s** | triage must stay near real-time so the queue never backs up; SLM-bound | `…{stage="triage"}` |
| SLM p95 | 50–90 s | 1 core, ~1 tok/s on the Pi (documented hardware reality) | `stage="slm"` |
| RAG p95 | < 1 s | local ChromaDB lookup | `stage="rag"` |
| LLM p95 (response time) | **< `LLM_TIMEOUT` (600 s)**, target < 420 s | report must land while the incident is fresh; flag every breach | `stage="llm"` |
| End-to-end (alert → report) p95 | < ~10 min | acceptable for a human-validated report on this hardware | `stage="total"` |
| `aegis.triage` peak depth | ≈ 0 during bursts | proves triage absorbs the flux (the two-stage win) | `rabbitmq_queue_messages` |
| `aegis.reports` | drains after the run | no permanent backlog | `rabbitmq_queue_messages` |
| LLM JSON-valid rate | 100 % | structured outputs; an invalid report falls back to SLM-only | middleware logs |
| Report field completeness | 100 % | a report missing fields isn't actionable | Level-1 |
| Action specificity (known rules) | 100 % | the action must name the real IP/endpoint (playbook) | Level-1 |
| Severity (confirmed attack) | ≥ high | a confirmed attack must not be diluted to medium | Level-1 |
| Alert loss under soak | **0** | losing alerts under load is unacceptable for a SOC | fired vs observed |
| SOAR delivery success | ≥ 99 % | reports must reach the human-validation workflow | `aegis_soar_deliveries_total` |
| Wazuh agent CPU | **< 5 %** (CLAUDE.md rule 2, non-negotiable) | exceeding it risks stopping industrial production | Wazuh API |

Targets are codified in [ADR 003](../adr/003-kpi-benchmark-protocol.md). The
MTTT before/after protocol is [ADR 002](../adr/002-mttt-measurement-protocol.md).

## Current results

### Level 1 — deterministic (`make benchmark-ci`, latest run on the seed corpus)

| KPI | Result | Threshold | Status |
|---|---|---|---|
| Attack recall (escalated) | 12 / 12 (100 %) | ≥ 95 % | ✅ |
| Report JSON-valid | 12 / 12 (100 %) | 100 % | ✅ |
| Action specificity | 12 / 12 (100 %) | 100 % | ✅ |
| Severity calibration | 12 / 12 ≥ floor | ≥ high (confirmed) | ✅ |
| UEBA gate matrix | 6 / 6 correct | 100 % | ✅ |
| False-positive rate (noise filter on) | 0 % | ≤ 5 % | ✅ |
| False-positive rate (noise filter off) | 33 % | — | ⚠️ shows why `WAZUH_EXCLUDED_RULES` matters |
| Identity connector (sync/idempotence/fallback) | pass | pass | ✅ |

Machine-readable snapshot: `docs/benchmarks/kpi-ci-latest.json` (regenerated each
run, git-ignored).

### Level 2 — live (`make benchmark`)

First live sample (2026-06-15, scenario B / SQLi, intensity smoke — 2 escalated
alerts, 1 completed LLM cycle on the Raspberry Pi):

| KPI | Measured | Threshold | Status |
|---|---|---|---|
| MTTT triage p50 / p95 | 45 s / 58.5 s | p95 < 90 s | ✅ |
| SLM p95 | 58.5 s | 50–90 s | ✅ |
| RAG p95 | 0.095 s | < 1 s | ✅ |
| LLM p95 (response time) | 291 s | < 600 s (target < 420) | ✅ |
| SOAR delivery success | 100 % | ≥ 99 % | ✅ |
| LLM JSON-valid rate | 100 % (1/1) | 100 % | ✅ |
| `aegis.triage` peak depth | 2 | ≈ 0 | ⚠️ tiny sample (2 near-simultaneous alerts, 1-core SLM) |

**Still pending**: a sustained `soak` run (hundreds of alerts, parallel Kali
tools) to validate backpressure / zero-loss under load, and Pi resource KPIs
(CPU/RAM/temperature) which need `node_exporter` on the Pi, plus the Wazuh-agent
CPU < 5 % check via the Wazuh API. These fill the remaining gaps and the ADR 002
"Before" column (pre-`b9cf8ad` architecture).
