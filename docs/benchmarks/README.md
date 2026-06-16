# AEGIS — Benchmarks & KPIs

KPIs organised by area — **Middleware**, **Pi (2 phases)**, **UEBA** — each with its
targets, latest results, and exact reproduction steps.

- **Deterministic KPIs** run anywhere in seconds (`make benchmark-ci`, no Pi).
- **Live KPIs** need the running stack + the Raspberry Pi inference node.

`p95` = 95th percentile (near-worst case). A **false positive** = a benign alert
(e.g. a host's netstat noise) escalated into a full LLM report.

---

## 1. Middleware KPIs — deterministic (`make benchmark-ci`)

The orchestration logic around the model: gating, escalation, report shape, action,
severity, false-positive control. Graded on a labeled corpus with a faked model, so
any failure is a code bug (not model variance).

| KPI | Target | Result (2026-06-15) |
|---|---|---|
| Attack recall (escalated) | ≥ 95 % | ✅ 100 % (12/12) |
| False-positive rate (noise filter on) | ≤ 5 % | ✅ 0 % |
| False-positive rate (filter off) | — | 33 % *(shows the filter's value)* |
| Report JSON valid / fields complete | 100 % | ✅ 100 % |
| Action specificity (cites real IP + endpoint) | 100 % | ✅ 100 % |
| Severity ≥ high for a confirmed attack | 100 % | ✅ 100 % |
| UEBA gate decisions (drop vs escalate) | 100 % | ✅ 6/6 |

**Reproduce**
```bash
make benchmark-ci        # writes docs/benchmarks/kpi-ci-latest.json
```

---

## 2. Pi — Phase 1: reports & false positives (`make benchmark-quality`)

Grades the **real model's reports** produced on the Pi against ground truth.

| KPI | Target | Result (smoke SQLi) |
|---|---|---|
| Action specificity (IP + endpoint) | 100 % | ✅ 100 % (`172.20.0.1` + `/rest/products/search`) |
| `attack_type` correct/specific | ≥ 90 % | ✅ 100 % ("SQL injection attempt") |
| Severity ≥ high | 100 % | ✅ 100 % |
| Report JSON valid (no fallback) | 100 % | ✅ 100 % |
| LLM analysis p95 | < 600 s | ✅ 291 s |
| Summary cites IP/endpoint | ≥ 60 % | ⚠️ 0 % — summary is correct but generic; KPI under review (the IP/endpoint live in the *action*) |
| Real recall | ≥ 90 % | ⚠️ 0.14 — not a model miss: only SQLi triggered a Wazuh rule on Juice Shop; XSS/traversal/cmd/recon raised no alert |

**Reproduce** (reports captured via a sink that stands in for the Shuffle webhook)
```bash
# 0. stack + Juice Shop up, Pi reachable
python -m scripts.benchmark.report_sink --port 8099 --reset --out /tmp/aegis-reports.jsonl &
GW=$(docker network inspect aegis-node1_aegis-monitoring -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
cp .env /tmp/.env.bak
sed -i "s#^SHUFFLE_WEBHOOK_URL=.*#SHUFFLE_WEBHOOK_URL=http://$GW:8099/#" .env
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware
make benchmark-quality SCENARIO=all          # fire (INTENSITY=smoke default)
# WAIT for the Pi (~3-9 min per escalated alert), then:
make benchmark-quality-score                 # writes docs/benchmarks/report-quality-<ts>.md
# RESTORE (important):
cp /tmp/.env.bak .env && docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware && pkill -f report_sink
```

---

## 3. Pi — Phase 2: load / montée en charge

Does AEGIS hold under a sustained flood? Measured over a **1 h Kali stress test**
(nikto + sqlmap + nmap + an 800-request web-attack flood ≈ **~100× the Pi's
real-time capacity**), sampling Prometheus/Grafana every 30 s (132 samples).

| KPI | Target | Measured under flood (avg / peak) | Verdict |
|---|---|---|---|
| Silent alert loss | 0 | **0** (698 overflow *parked* in `aegis.deadletter`, 0 discarded) | ✅ |
| Pi temperature | < 80 °C | 67.9 °C / **70.0 °C** | ✅ no throttling |
| Pi RAM used | stable | 45.5 % / 45.6 % | ✅ never a constraint |
| Pi CPU | < 90 % | 96 % / **100 %** | ⚠️ saturated — the bottleneck |
| MTTT triage p95 | < 90 s | 219 s / **291 s** (→ 58 s as it drains) | ⚠️ exceeded under flood |
| Report throughput | — | **~8 reports / hour** (sink) | capacity limit |
| Queue peak (triage / deadletter) | — | 840 / 698 | absorbed, not lost |

**Interpretation.** Under ~100× overload AEGIS degrades **gracefully, not
catastrophically**: CPU pegs at 100 % but the Pi stays thermally safe and RAM-stable,
the durable broker absorbs the backlog, triage latency rises then recovers as the
flood subsides, and **nothing is silently lost** — overflow beyond the 1 h TTL is
parked in `aegis.deadletter` for human review. The hard limit is **compute capacity**
(~8 reports/h on one Pi), not reliability. To sustain higher rates: a faster Pi,
parallel triage, or a second inference node.

> **Zero-loss model:** `aegis.triage` and `aegis.reports` are durable with persistent
> messages, a 1 h TTL and a dead-letter exchange — an alert that can't be analysed in
> time is *parked* in `aegis.deadletter`, never dropped. See
> [poc-linux-startup.md → Message reliability](../runbooks/poc-linux-startup.md#message-reliability--queue-ttl-dead-letter--overload).

**Reproduce.** Drive a real attacker from a Kali VM (see the POC runbook, Partie E,
"Mise en tension"), or `make benchmark-load` (web-replay from Node 1), then aggregate
the window from Prometheus. Pi CPU/RAM/temperature need a `node_exporter` on the Pi.

---

## 4. UEBA — pluggable DB, auto-update & behavioral scoring

UEBA context comes from an identity store and must (a) work with **any** store, (b)
**update itself**, and (c) score **behavior**, not just privilege. The store is
pluggable via the `BaseIdentityConnector` seam (LDAP today, Active Directory/Okta =
a new adapter, nothing else changes). An alert on an **unprofiled asset**
auto-enqueues a sync that populates its context.

These KPIs are **rates over a population** (assets, attacks), not single pass/fail
checks — measured deterministically and written to `kpi-ci-latest.json`.

### 4.1 Coverage, detection & gate (measured)

| KPI | Definition (population) | Target | Measured (2026-06-15) |
|---|---|---|---|
| **Sync coverage** | directory assets profiled in UEBA / total | 100 % | ✅ 100 % (6/6) |
| **Tier correctness** | profiled assets with the right criticality / total | 100 % | ✅ 100 % (6/6) |
| **Identity-attack detection** | corpus identity attacks (rules 100xxx) escalated / total | 100 % | ✅ 100 % (5/5) |
| **Gate decision matrix** | correct escalate/discard decisions / cases | 100 % | ✅ 100 % (7/7) |
| **Connector fallback (DB down)** | degrades gracefully, no crash | graceful | ✅ |
| **Connector idempotence** | re-sync creates no duplicate | yes | ✅ |
| **Auto-sync on unprofiled / dedup** | sync triggered on unknown asset / 1 per burst | 100 % / 1 | ✅ |

### 4.2 Behavioral anomaly score — Gap 2 (measured)

`anomaly_score` is now a **behavioral** signal (trailing event window + EWMA
baseline in `aegis.rag.ueba`), decoupled from privilege — privilege stays in the
asset tier / risk-scorer criticality multiplier. A burst above an asset's own
baseline raises the score; sustained load is absorbed back to normal.

| KPI | Target | Measured |
|---|---|---|
| Score at rest (activity ≈ baseline) | ≤ 0.10 | ✅ 0.00 |
| Score at burst peak (≥ baseline × 3) | ≥ 0.80 | ✅ 1.00 |
| Score decays after sustained load | back to rest | ✅ 0.005 |
| Score stays bounded `[0,1]` | strict | ✅ |

**Reproduce** (deterministic, no Pi)
```bash
make benchmark-ci    # runs the benchmark suite; writes docs/benchmarks/kpi-ci-latest.json
# UEBA-only:
.venv/bin/pytest tests/benchmarks/test_ueba_kpis.py tests/benchmarks/test_connector_kpis.py \
  tests/benchmarks/test_ueba_population_kpis.py tests/benchmarks/test_anomaly_kpis.py -m benchmark
```

---

## Appendix

- **Artifacts** (git-ignored, regenerated each run): `docs/benchmarks/kpi-ci-latest.json`,
  `report-*.{md,json}`, `report-quality-*.{md,json}`.
- **Scenarios**: `scripts/benchmark/scenarios.py` (A recon, B SQLi, C XSS, D traversal,
  E cmd-injection, F brute-force). High-value custom rules (100001-100042), which Kali
  can't trigger on Juice Shop, are covered by `tests/fixtures/corpus/` at Level 1.
- **Gotcha**: recreating the middleware container spins new `veth` interfaces → `dockerd`
  fires rule 80710 (promiscuous), which can show up as 1-2 extra captured "reports". The
  scorer ignores any report that doesn't match a fired scenario, so KPIs are unaffected.
