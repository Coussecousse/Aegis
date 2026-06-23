# AEGIS — UEBA (identity + behavior)

UEBA gives each alert **context about the asset under attack**: how critical it is,
and whether it is behaving abnormally. AEGIS uses that context to (a) avoid drowning
the operator in noise and (b) prioritise what matters. It has three promises:

1. **Pull context from any identity store** — and fill in **completely & correctly**.
2. **Update itself** — a never-seen asset auto-populates its profile.
3. **Score behavior, not just privilege** — a real deviation over time raises risk.

KPIs and measured results: [benchmarks/README.md §4](benchmarks/README.md).

> **Note on "RAG"**: The `rag/` module historically contained ChromaDB for vector
> similarity search, but **AEGIS never used vector search in production**. The actual
> use case is key-value lookup for asset profiles + time-series for UEBA behavioral
> scoring. As of v1.0, the identity store is **PostgreSQL** with native auth,
> encryption at rest (LUKS), and TTL enforcement — addressing security requirements
> for NIS 2 / GDPR compliance.

## Vocabulary

- **asset** — a monitored host/identity (keyed by `source_ip` / hostname).
- **profiled** — AEGIS already has the asset's context in PostgreSQL (`has_baseline=True`).
- **criticality / tier** — privilege of the asset: `tier0` (critical, e.g. a DC) →
  `tier2` (ordinary). Drives the risk **criticality multiplier**.
- **anomaly_score** — *behavioral* deviation in `[0,1]`, separate from privilege.

## 1. Pluggable identity store

The store sits behind the [`BaseIdentityConnector`](../src/aegis/rag/base.py) seam.
[`LdapConnector`](../src/aegis/rag/ldap.py) implements it for LDAP/Active Directory;
swapping to Okta/another store is a new adapter and **nothing else changes**.
`PostgresIdentityStore.sync_asset_identity()` runs the ETL: connector → `RagContext` →
PostgreSQL. If the store is unreachable it degrades gracefully (default tier2
profile), never crashing the pipeline.

## 2. Auto-update (event-driven sync)

When triage sees an alert on an **unprofiled** asset, it enqueues an `identity.sync`
job for that asset (with in-process TTL **dedup** so a burst enqueues one job). The
[identity worker](../src/aegis/middleware/consumer_identity.py) then pulls the asset's
context into PostgreSQL. Self-limiting: once profiled, `has_baseline` flips True and
triage stops asking.

## 3. The triage gate

The UEBA false-positive gate ([pipeline.py](../src/aegis/middleware/pipeline.py))
discards an alert **only** when *all* hold: the asset has a real baseline, anomaly is
low, the rule level is ≤ 8, the asset is non-critical, **and** the SLM was only weakly
suspicious (confidence < `FP_GATE_CONFIDENCE_CEILING`, default 0.6). So genuine noise
on a calm ordinary host is dropped, but a **confident** detection — or anything on a
critical asset — always escalates.

## 4. Behavioral scoring — Gap 2 ([`rag/ueba.py`](../src/aegis/rag/ueba.py))

`anomaly_score` is a **behavioral** signal, decoupled from privilege (privilege lives
in the tier / criticality multiplier). A simple, explainable heuristic — no ML:

- a **trailing event window** (last 5 min) counts the asset's recent activity;
- an **EWMA baseline** learns the asset's normal rate over time;
- `anomaly_score = 0` at/below baseline, rising to `1.0` at `baseline × 3`;
- after a sustained burst the EWMA baseline catches up, so the score **decays** back
  to normal (the activity becomes the "new normal").

`record_activity()` updates this per alert, using the **alert's own timestamp**, and
persists the window + baseline in PostgreSQL (`asset_profiles` table for baselines,
`ueba_activity` partitioned table for event time-series). Worked example from a live burst:

```
events_in_window:  1     2     3     4     5  …  14
anomaly_score:    0.00  0.50  0.75  0.78  0.72 … 0.26   (rise → peak ~0.78 → decay)
baseline (EWMA):  1.0   1.2   1.56  2.05  2.64 … 10.2
```

The score feeds the risk math via `ueba_factor = 0.70 + anomaly_score × 0.30`: an
asset deviating from its baseline gets a higher `danger_score`; a calm one is damped.

### How EWMA baseline learns: technical details

The baseline is **not a moving average of recent activity** — it's an **exponential weighted moving average (EWMA)** that adapts gradually as behavior changes.

**Formula** (`rag/ueba.py:76`):
```
baseline_new = (1 - α) × baseline_old + α × recent_count
```

Where:
- `α` (**alpha**) = `DEFAULT_BASELINE_ALPHA = 0.2` (20% weight to new observation)
- `baseline_old` = the learned "normal" rate from before this alert
- `recent_count` = events observed in the last 5 minutes
- `baseline_new` = updated baseline, rounded to 3 decimals

**Why this works**:
1. **Gradual adaptation** — `α=0.2` means new activity is weighted at 20%, old baseline at 80%. A single anomalous spike doesn't flip the baseline.
2. **Sustained activity becomes normal** — if high activity *continues*, the baseline gradually rises (0.2 per alert) until it matches the new normal, and `anomaly_score` decays back to ~0.
3. **Self-healing** — when activity drops back to baseline, the score returns to 0 without manual reset.

**Example walkthrough** (from the table above):
- Initial: baseline = 1.0, recent_count = 1 → `baseline_new = 0.8×1.0 + 0.2×1 = 1.0` → anomaly_score = 0
- Event 2: recent_count = 2 → `baseline_new = 0.8×1.0 + 0.2×2 = 1.2` → anomaly_score = (2-1)/(1×2) = 0.50
- Event 3: recent_count = 3 → `baseline_new = 0.8×1.2 + 0.2×3 = 1.56` → anomaly_score = (3-1.2)/(1.2×2) = 0.75
- Event 14: recent_count = 14 → `baseline_new = 0.8×10.2 + 0.2×14 ≈ 10.96` → anomaly_score = (14-10.2)/(10.2×2) ≈ 0.19 **(decay)**

**Floor behavior** — baseline never drops below `_MIN_BASELINE = 1.0`, so a newly-seen quiet asset isn't hyper-sensitive to 1–2 events.

### How it shows up in a report

```jsonc
"rag_context": { "ueba": { "has_baseline": true, "anomaly_score": 0.75, … } },
"risk_score":  { "score_breakdown": { "criticality_multiplier": 1.0,   // privilege
                                       "ueba_factor": 0.925 } }          // behavior
```

## Reproduce the KPIs

```bash
.venv/bin/pytest tests/benchmarks/test_ueba_kpis.py tests/benchmarks/test_connector_kpis.py \
  tests/benchmarks/test_ueba_population_kpis.py tests/benchmarks/test_anomaly_kpis.py -m benchmark
```
