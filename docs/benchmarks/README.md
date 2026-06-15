# AEGIS KPI / Benchmark Guide

What we measure on AEGIS, **why, how each number is computed, and the target to
hit** — so we know what to expect (report quality, response time, false-positive
rate…) in a reproducible way.

---

## 1. Vocabulary (read this first)

- **Alert** — an event Wazuh detects (e.g. "SQL injection attempt").
- **Triage (fast stage, SLM model)** — for each alert, a small model quickly decides
  whether to **drop** it (noise) or **escalate** it (worth a closer look).
- **Escalation** — when triage decides an alert is worth analyzing.
- **Analysis (slow stage, LLM model)** — a larger model writes the detailed **report**
  (attack type, summary, recommended action). Slow (minutes) on the Raspberry Pi.
- **Report** — the final output, then validated by a human.
- **p50 / p95** — ways to summarize a set of durations. p50 = the median (half the alerts
  are faster). p95 = the "near-worst case" (95 % are faster; ignores the worst 5 %). We set
  targets on **p95** because that is what the user feels on bad runs.

---

## 2. What the tests actually do

Two families, two commands.

### Level 1 — fast automated checks (`make benchmark-ci`)
Run on a normal PC, **without the Raspberry Pi**, in seconds. They replay a **labeled
alert corpus** (we already know the right answer) with the models faked, to check the
**deterministic** behaviour:
- reports carry all fields and a **concrete action** (the real IP / endpoint);
- the assigned **severity** is consistent;
- the **UEBA gate** (drop vs escalate) makes the right calls;
- the **false-positive rate** (see §3);
- the **identity connector** (LDAP→DB) works, even when LDAP is down.

### Level 2 — real run on the stack + Pi, in **two phases**
Fires **real attacks** at the target and measures the **real** behaviour. Split by intent:

- **Phase 1 — Quality** (`make benchmark-quality`): low volume, replays the labeled
  attacks and **grades the real model's reports** against ground truth — does the Pi
  detect, escalate (or not), and write a good report? See §6.
- **Phase 2 — Load** (`make benchmark-load`): a sustained **soak** (hundreds of alerts,
  parallel) to check **throughput, zero alert loss, latency under load, and Pi
  resources**. See §6.

> **We accept that AEGIS does not yet meet every target.** The KPIs are diagnostic
> goals to track progress, **not** blocking gates. Phase-1 targets especially are
> **provisional — to calibrate** against the real project.

---

## 3. The KPIs: definition, how it's computed, target

For each KPI: **what it is → how we compute it → the target (and why)**.

### False-positive rate — ≤ 5 %
- **What it is** — a false positive is an alert that is **not a real attack** but that
  AEGIS escalates anyway, all the way to a report. Concrete example: on the host running
  AEGIS, "netstat: a port changed" (rule 533) is **normal** activity, not an attack — if
  AEGIS writes a report for it, that's a false positive.
- **How it's computed** — we replay a set of **known-benign alerts** (labeled "not an
  attack" in the corpus), then:

  `FP rate = (benign alerts escalated to a report) ÷ (total benign alerts)`

- **Target: ≤ 5 %.** Why: each false positive burns **one 5–9 min LLM cycle** on the Pi
  and drowns the real signal. A little is tolerable, a lot is not.
- **Measured today** — **0 %** with the noise filter on (`WAZUH_EXCLUDED_RULES=533`),
  **33 %** without it (the netstat alert slips through). That quantifies the filter.

### Attack recall (miss nothing) — ≥ 95 % (aim for 100 %)
- **What it is** — the share of **real attacks** that get escalated.
- **How** — `(real attacks escalated) ÷ (total real attacks in the corpus)`.
- **Target ≥ 95 %.** Why: missing a real attack is the worst failure for a SOC.

### Response time — triage and analysis
- **MTTT (triage time), p95 < 90 s.** Time the fast stage takes to decide drop/escalate.
  Computed by recording each triage duration and reading the p95. Why 90 s: triage must
  stay near real-time so no backlog builds up.
- **LLM analysis time, p95 < 600 s (ideally < 420 s).** Time to write a report. Slow
  because the Pi runs on CPU. Why 600 s: that's the configured budget (`LLM_TIMEOUT`);
  beyond it the analysis is abandoned.
- **End-to-end (alert → report), p95 < ~10 min.** Acceptable for a human-validated report
  on this hardware.

### Throughput under load (attack burst)
- **Triage queue ≈ 0 during a burst.** Computed as the peak number of messages waiting in
  `aegis.triage`. Why: proves triage absorbs the flux without piling up.
- **Alert loss = 0.** Computed as alerts sent vs alerts actually processed. Why: losing an
  alert under load is unacceptable for a SOC.

### Report quality
- **Valid JSON report = 100 %** — a malformed report is unusable (it falls back to a
  degraded analysis). Computed as valid ÷ produced.
- **Field completeness = 100 %** — the 10 expected fields are present.
- **Concrete action = 100 % (on known rules)** — the recommended action names the **real
  IP / endpoint** (e.g. "Block 172.20.0.1 at the firewall; audit /rest/products/search"),
  not generic advice.
- **Severity ≥ "high" for a confirmed attack** — a confirmed attack must not be downgraded
  to "medium".

### Robustness / constraints
- **SOAR delivery ≥ 99 %** — reports reach the human-validation workflow.
- **Wazuh agent CPU < 5 %** (project's non-negotiable rule) — above it, risk of impacting
  industrial production.

---

## 4. How to run the tests

```bash
# Level 1 — fast, no Pi. Writes docs/benchmarks/kpi-ci-latest.json
make benchmark-ci

# Level 2 — real (stack + Pi up). Writes docs/benchmarks/report-<date>.md
make benchmark SCENARIO=all INTENSITY=standard
#   INTENSITY=smoke    -> a few alerts (quick check)
#   INTENSITY=standard -> dozens of alerts
#   INTENSITY=soak     -> hundreds, in parallel (the "lots of logs" load test)

# Manual two-step variant:
python -m scripts.benchmark.run_attack_suite --scenario B --intensity smoke   # attack
python -m scripts.benchmark.collect_kpis --since <T0> --until <T1>            # measure
```

Attack scenarios (A recon, B SQLi, C XSS, D path-traversal, E command-injection,
F brute-force, …) are defined once in `scripts/benchmark/scenarios.py`. High-value rules
that can't be triggered from Kali (AD account, ransomware, C2…) are covered by the Level-1
labeled corpus.

---

## 5. Current results

### Level 1 (latest `make benchmark-ci`) — all within target
| KPI | Result | Target | Status |
|---|---|---|---|
| Attack recall | 12/12 (100 %) | ≥ 95 % | ✅ |
| Valid JSON report | 12/12 | 100 % | ✅ |
| Concrete action | 12/12 | 100 % | ✅ |
| Severity consistent | 12/12 | ≥ high if confirmed | ✅ |
| UEBA gate decisions | 6/6 | 100 % | ✅ |
| False-positive rate (filter ON) | 0 % | ≤ 5 % | ✅ |
| False-positive rate (filter OFF) | 33 % | — | ⚠️ shows the filter's value |
| Identity connector | OK | OK | ✅ |

Machine-readable snapshot: `docs/benchmarks/kpi-ci-latest.json` (regenerated each run,
git-ignored).

### Level 2 (first live sample, 2026-06-15, SQLi, smoke intensity)
2 escalated alerts, 1 full LLM report on the Pi:

| KPI | Measured | Target | Status |
|---|---|---|---|
| MTTT triage p50 / p95 | 45 s / 58.5 s | p95 < 90 s | ✅ |
| LLM analysis time p95 | 291 s | < 600 s | ✅ |
| RAG (context lookup) p95 | 0.095 s | < 1 s | ✅ |
| SOAR delivery | 100 % | ≥ 99 % | ✅ |
| Valid JSON report | 100 % (1/1) | 100 % | ✅ |
| Triage queue peak | 2 | ≈ 0 | ⚠️ tiny sample (2 near-simultaneous alerts) |

**Still to do**: a real `soak` load run (validate throughput / zero loss under hundreds of
alerts), and the **Pi resource KPIs** (CPU/RAM/temperature via `node_exporter`) plus the
**Wazuh agent CPU < 5 %** check.

---

## 6. Level 2 in two phases

### Phase 1 — Quality (does the Pi react correctly?)

Replays the labeled attacks for real and **grades the model's actual reports** against
ground truth. Reports are captured non-invasively: a small sink stands in for the SOAR
webhook (the pipeline already POSTs the full report there).

```bash
# 1. start the capture sink (host), reset the capture file
python -m scripts.benchmark.report_sink --port 8099 --reset --out /tmp/aegis-reports.jsonl
# 2. point the middleware's SHUFFLE_WEBHOOK_URL at the sink and recreate it, e.g.
#    SHUFFLE_WEBHOOK_URL=http://host.docker.internal:8099/  (reachable from the container)
# 3. fire the attacks (writes a manifest)
make benchmark-quality SCENARIO=all          # INTENSITY=smoke by default
# 4. WAIT for the Pi to produce reports (5-9 min each), then grade them
make benchmark-quality-score                 # writes docs/benchmarks/report-quality-<ts>.md
```

| Phase-1 KPI | How it's computed | Target (provisional) |
|---|---|---|
| Real recall | attack scenarios that produced a report ÷ attacks fired | ≥ 90 % |
| Real false-positive rate | benign that produced a report ÷ benign | ≤ 10 % |
| Report JSON-valid rate | reports with an LLM analysis ÷ reports | ≥ 95 % |
| Severity accuracy | `decision.severity` ≥ expected floor | ≥ 80 % |
| Action specificity | action contains the real attacker IP **and** endpoint | ≥ 80 % |
| `attack_type` relevance | contains an attack keyword (sql/xss/traversal…) | ≥ 70 % |
| Summary specificity | summary cites the actor or endpoint | ≥ 60 % |

> Custom rules (100001-100042) can't be fired from Kali against Juice Shop, so their
> quality stays covered by the Level-1 corpus.

### Phase 2 — Load (does it hold under a storm?)

```bash
make benchmark-load SCENARIO=all INTENSITY=soak   # soak = hundreds, parallel
# writes docs/benchmarks/report-<ts>.md with latency + zero-loss + Pi resources
```

| Phase-2 KPI | How it's computed | Target (provisional) |
|---|---|---|
| MTTT triage p95 under load | Prometheus, stays near the no-load value | < 90 s |
| Alert loss | Wazuh alerts in window (level≥7) − alerts entering the pipeline | 0 |
| `aegis.triage` peak / drain | queue depth peak; drains after the run | drains |
| Pi CPU / temperature | node_exporter | < ~90 % / < 80 °C |
| Wazuh agent CPU | Wazuh API (manual until wired) | < 5 % |

Pi resource KPIs need a `node_exporter` scraped by Prometheus; they read `None` otherwise.

---

## 7. References

- Targets formalized in [ADR 003](../adr/003-kpi-benchmark-protocol.md).
- MTTT before/after protocol in [ADR 002](../adr/002-mttt-measurement-protocol.md).
