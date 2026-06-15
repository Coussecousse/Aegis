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

## 3. Pi — Phase 2: load / montée en charge (`make benchmark-load`)

A sustained soak (hundreds of alerts, parallel) — does AEGIS hold?

| KPI | Target | Result |
|---|---|---|
| MTTT triage p95 (under load) | < 90 s | ✅ 58.5 s (sample) |
| Alert loss | 0 | ✅ 0 |
| `aegis.triage` drains / `aegis.reports` drains after run | drains | ✅ |
| SOAR delivery | ≥ 99 % | ✅ 100 % |
| Pi CPU / temperature | < 90 % / < 80 °C | 64 % / 68 °C |
| Wazuh agent CPU | < 5 % | _measure via Wazuh API_ |

**Reproduce**
```bash
make benchmark-load SCENARIO=all INTENSITY=soak   # writes docs/benchmarks/report-<ts>.md
```
Pi CPU/RAM/temperature need a `node_exporter` on the Pi scraped by Prometheus
(else they read `None`).

---

## 4. UEBA — pluggable DB + auto-update

UEBA context comes from an identity store and must (a) work with **any** store and
(b) **update itself**. The store is pluggable via the `BaseIdentityConnector` seam
(LDAP today, Active Directory/Okta = a new adapter, nothing else changes). An alert
on an **unprofiled asset** auto-enqueues a sync that populates its context.

| KPI | Target | Result |
|---|---|---|
| Auto-sync triggered on unprofiled asset | 100 % | ✅ |
| No sync when already profiled | 100 % | ✅ |
| Dedup under burst (same asset → 1 sync) | 1 | ✅ |
| Connector fallback when the DB is down | graceful | ✅ |
| Time-to-profile (after sync → `has_baseline=True`) | profiled | ✅ |

**Reproduce** (deterministic, no Pi)
```bash
make test    # tests in tests/unit/middleware/ + tests/integration/test_pipeline.py
```

> **Next (UEBA Gap 2)**: a behavioral, time-based `anomaly_score` (replacing the
> current identity-derived heuristic), with its own KPIs.

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
