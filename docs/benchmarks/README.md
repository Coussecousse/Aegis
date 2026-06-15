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

## SLO targets (provisional — first representative run sets the baseline)

| KPI | Target | Source |
|---|---|---|
| MTTT (triage) p95 | < 90 s (SLM-bound) | `aegis_pipeline_duration_seconds{stage="triage"}` |
| SLM p95 | 50–90 s | `stage="slm"` |
| RAG p95 | < 1 s | `stage="rag"` |
| LLM p95 | 240–700 s (flag > `LLM_TIMEOUT`) | `stage="llm"` |
| `aegis.triage` peak depth | ≈ 0 during bursts | `rabbitmq_queue_messages` |
| `aegis.reports` | drains after the run | `rabbitmq_queue_messages` |
| LLM JSON-valid rate | 100 % (structured outputs) | middleware logs |
| Report field completeness | 100 % | Level-1 KPI |
| Action specificity (known rules) | 100 % | Level-1 KPI |
| Severity (confirmed attack) | ≥ high | Level-1 KPI |
| Alert loss under soak | 0 | event count vs alerts fired |
| SOAR delivery success | ≥ 99 % | `aegis_soar_deliveries_total` |
| Wazuh agent CPU | < 5 % (CLAUDE.md rule 2) | Wazuh API |

Targets are codified in [ADR 003](../adr/003-kpi-benchmark-protocol.md). The
MTTT before/after protocol is [ADR 002](../adr/002-mttt-measurement-protocol.md).
