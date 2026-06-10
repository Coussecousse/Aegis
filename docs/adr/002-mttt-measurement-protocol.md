# ADR 002: MTTT measurement protocol for the partitioned Ollama architecture

- Status: Accepted
- Date: 2026-06-10

## Context

Before this change, both pipeline stages shared a single `asyncio.Semaphore(1)`
guarding all Ollama calls. A single Ollama instance fully serialized SLM triage
(`triage_log()`, queue `aegis.triage`) and LLM analysis (`analyze_log()`, queue
`aegis.reports`): a multi-minute Mistral analysis on the Raspberry Pi blocked
every subsequent triage call for its entire duration, so `aegis.triage` could
back up indefinitely during a sustained attack.

Commits `b9cf8ad` / `53a58c5` / `adeb4ee` replaced this with two independent,
CPU-pinned `ollama serve` instances (see `docs/raspberrypi-ollama-setup.md`):

| Instance | Port | Cores | Model | Used by |
|---|---|---|---|---|
| `ollama-slm` | 11434 | 1 | `qwen25-aegis` | `triage_log()` |
| `ollama-llm` | 11435 | 3 | `mistral-aegis` | `analyze_log()` |

The hypothesis: MTTT (Mean Time To Triage — the time `triage_log()` takes to
reach a discard/escalate decision for one alert) should stay flat regardless of
how many alerts are simultaneously in LLM analysis, and the `aegis.triage`
queue should not back up during an LLM-heavy window.

This ADR defines how that hypothesis is measured — the metrics involved, the
PromQL to read them, and the before/after protocol — and a placeholder for the
results once a Kali attack run is captured for both architectures.

## Decision

### Metrics

- **MTTT** — `aegis_pipeline_duration_seconds_bucket{stage="triage"}`
  (`MetricsCollector.record_triage()`). Observed on every `triage_log()` exit
  path: suspicion-gate discard, RAG error, UEBA-gate discard, and escalation.
  This is the primary signal — previously the escalation path recorded no
  triage-duration observation at all.
- **SLM/LLM step durations** —
  `aegis_pipeline_duration_seconds_bucket{stage="slm"|"llm"}` (pre-existing
  `record_slm` / `record_llm`), used to confirm the LLM stage absorbs the
  multi-minute cost while `stage="slm"` stays in the 8-18s range documented in
  `docs/raspberrypi-ollama-setup.md`.
- **`aegis.triage` backlog** —
  `rabbitmq_queue_messages{queue="aegis.triage", vhost="aegis"}` (and
  `aegis.reports` for comparison), now exposed via
  `prometheus.return_per_object_metrics = true`
  (`docker/node1/rabbitmq/config/rabbitmq.conf`).

### PromQL reference

```promql
# MTTT p50 / p95 over a 5-minute window
histogram_quantile(0.50, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="triage"}[5m])) by (le))
histogram_quantile(0.95, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="triage"}[5m])) by (le))

# SLM / LLM step durations
histogram_quantile(0.95, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="slm"}[5m])) by (le))
histogram_quantile(0.95, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="llm"}[5m])) by (le))

# aegis.triage / aegis.reports backlog
rabbitmq_queue_messages{queue="aegis.triage", vhost="aegis"}
rabbitmq_queue_messages{queue="aegis.reports", vhost="aegis"}
```

All four series are visualized on the AEGIS Crisis dashboard
(`docker/node1/grafana/dashboards/crisis.json`, panels "MTTT — Triage Duration
p50/p95", "SLM Triage Duration p95", "LLM Analysis Duration p95", and "Queue
Depth — aegis.triage / aegis.reports").

### Protocol

1. **Before** (single shared Ollama instance / semaphore — pre-`b9cf8ad`): run
   a sustained attack scenario (noise phase + a high-severity event expected to
   trigger LLM escalation, see the upcoming Juice Shop/Kali runbook under
   `docs/runbooks/`) and record MTTT p50/p95, `stage="llm"` p95, and
   `aegis.triage` peak depth during the high-severity window.
2. **After** (partitioned instances, current `HEAD`): redeploy with the
   partitioned Ollama systemd units (`ollama-slm` / `ollama-llm`) and rerun the
   identical scenario, recording the same three figures.
3. Compare MTTT p50/p95 and `aegis.triage` peak depth between the two runs. The
   architecture is validated if MTTT stays within its baseline range (~8-18s,
   per `docs/raspberrypi-ollama-setup.md`) during the LLM-heavy window in the
   "after" run, even though `stage="llm"` durations are unchanged (still
   minutes).

## Consequences (positive)

- A single `stage="triage"` series gives MTTT for every alert outcome
  (discard/error/escalate), closing the gap where escalated alerts previously
  recorded no triage-duration metric at all.
- Queue depth and stage durations are visible on one dashboard during a live
  attack, without ad-hoc `rabbitmqctl` calls.
- The before/after comparison is reproducible: same scenario, same dashboard,
  different `OLLAMA_*_BASE_URL` wiring.

## Consequences (negative)

- `aegis_pipeline_duration_seconds{stage="total"}` keeps its pre-existing,
  slightly conflated meaning (triage-stage duration for `discarded`/`error`
  alerts, analysis-stage-only duration for `processed` alerts) — left
  unchanged to avoid disrupting the existing "Pipeline Duration p95" panel.
  `stage="triage"` is the metric to use for MTTT going forward.
- `prometheus.return_per_object_metrics = true` adds a small per-scrape
  overhead proportional to the number of queues/exchanges (negligible at
  AEGIS's scale: 4 queues).
- The new RabbitMQ config requires a container restart
  (`docker compose up -d --force-recreate rabbitmq` or equivalent) before
  queue-depth panels populate.

## Results

_To be filled in after running the Kali attack scenario against both
architectures._

| Metric | Before (shared semaphore) | After (partitioned instances) |
|---|---|---|
| MTTT p50 (s) | _TBD_ | _TBD_ |
| MTTT p95 (s) | _TBD_ | _TBD_ |
| `stage="llm"` p95 (s) | _TBD_ | _TBD_ |
| `aegis.triage` peak depth | _TBD_ | _TBD_ |
