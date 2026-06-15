# ADR 003: KPI / benchmark protocol for AEGIS

- Status: Accepted
- Date: 2026-06-15

## Context

AEGIS had instrumentation (`MetricsCollector` → Prometheus, the Grafana crisis
dashboard, the MTTT protocol in [ADR 002](002-mttt-measurement-protocol.md)) but
no catalogue of KPIs, no targets/SLOs, no reproducible measurement harness, and
no ground truth. Attack scenarios lived in a stale, drifting runbook
(`load-test-juiceshop-kali.md`). We need to know — repeatably and with numbers —
what to expect from reports, timings, the UEBA behaviour, the UEBA↔ChromaDB
connector, resilience, and resource use.

## Decision

Adopt a **two-level KPI harness** with a single source of truth, documented in
[`docs/benchmarks/README.md`](../benchmarks/README.md):

- **Level 1 (deterministic, no Pi)** — `make benchmark-ci` runs
  `tests/benchmarks/` against a labeled corpus (`tests/fixtures/corpus/`) with a
  fake model, measuring report structure/action-specificity/severity
  calibration, the UEBA gate matrix, and the identity connector. Writes
  `docs/benchmarks/kpi-ci-latest.json`.
- **Level 2 (live)** — `make benchmark` replays the attack-scenario matrix
  (`scripts/benchmark/scenarios.py`, the single source of truth, intensities
  smoke/standard/soak) and `collect_kpis.py` computes latency/throughput/
  semantic KPIs from Prometheus + middleware logs into
  `docs/benchmarks/report-<ts>.md`.

KPI categories: latency per stage, throughput/backpressure, report quality,
UEBA & scoring, identity connector, resilience, resources, detection coverage.
Provisional SLO targets are tabulated in the benchmarks README; the first
representative live run sets the baseline and fills the ADR 002 Results table.

The custom rules (100001-100042) that Kali cannot trigger against Juice Shop are
covered as a synthetic labeled corpus at Level 1. The standalone load-test
runbook is removed; scenarios live in the harness only.

## Consequences (positive)

- Reproducible, numeric expectations for every subsystem; regressions are visible.
- One place to add a scenario (a corpus entry and/or `scenarios.py`); no runbook drift.
- CI can gate on Level-1 KPIs without the Pi; live KPIs use the same definitions.

## Consequences (negative)

- Semantic report quality and all latency/resource KPIs require the live Pi.
- Generated run artifacts are git-ignored, so historical baselines must be
  recorded deliberately (ADR 002 Results, or committed report snapshots).
- The labeled corpus is a maintained artifact: new detections need corpus entries.
