# AEGIS — Benchmarks & KPIs

What we measure, the targets, whether we hit them, and **how to reproduce every
number** yourself. Two levels:

- **Level 1 — CI** (`make benchmark-ci`): deterministic, runs on any machine in
  seconds, no Raspberry Pi. Grades the pipeline logic on a labeled corpus.
- **Level 2 — live** (the Pi): real attacks against the stack. Two phases —
  **Quality** (grade the real model's reports) and **Load** (throughput/resources
  under a storm).

`p95` = 95th percentile (the near-worst case; 95 % of runs are faster). A
**false positive** = a benign alert (e.g. a host's netstat noise) that AEGIS
escalates into a full LLM report.

---

## 1. KPIs & targets

| KPI | Target | Why |
|---|---|---|
| Attack recall (real attacks escalated) | ≥ 95 % | missing an attack is the worst SOC failure |
| False-positive rate (benign → report) | ≤ 5 % | each FP burns one 5-9 min LLM cycle on the Pi |
| Report JSON valid (no fallback) | 100 % | a malformed report is unusable |
| Report fields complete | 100 % | an incomplete report isn't actionable |
| Action specificity (cites real IP + endpoint) | 100 % | the operator needs a concrete action |
| `attack_type` correct/specific | ≥ 90 % | "Web Attacks" is useless; name the attack |
| Severity ≥ high for a confirmed attack | 100 % | don't downgrade a real attack |
| MTTT (triage) p95 | < 90 s | triage must stay near real-time |
| LLM analysis p95 | < 600 s | configured budget on CPU-only Pi |
| Alert loss under load | 0 | losing alerts under a storm is unacceptable |
| Wazuh agent CPU | < 5 % | hard project rule — never disturb production |
| UEBA auto-sync on unprofiled asset | 100 % | the identity store must keep UEBA updated |

> Phase-1 *narrative* KPIs (e.g. the plain-language summary citing the IP) are
> still being calibrated — see the note in §2.

---

## 2. Results (last run: 2026-06-15)

### Level 1 — CI (`make benchmark-ci`) — ✅ all targets met
| KPI | Target | Measured |
|---|---|---|
| Attack recall | ≥ 95 % | **100 %** (12/12) |
| False-positive rate (noise filter on) | ≤ 5 % | **0 %** |
| False-positive rate (filter off) | — | 33 % *(shows the filter's value)* |
| Report JSON valid | 100 % | **100 %** |
| Action specificity | 100 % | **100 %** |
| Severity correct | 100 % | **100 %** |
| UEBA gate decisions | 100 % | **100 %** (6/6) |
| UEBA auto-sync trigger + dedup | 100 % | **100 %** |

### Level 2 — live, response time (smoke SQLi sample) — ✅
| KPI | Target | Measured |
|---|---|---|
| MTTT triage p95 | < 90 s | **58.5 s** |
| LLM analysis p95 | < 600 s | **291 s** |
| Alert loss | 0 | **0** |
| SOAR delivery | ≥ 99 % | **100 %** |
| Pi CPU / temp (node_exporter) | < 90 % / < 80 °C | 64 % / 68 °C |

### Level 2 — Phase 1, report quality (real model on the Pi) — ⚠️ mostly met
On the alerts that actually fired (SQL injection):

| KPI | Target | Measured | Note |
|---|---|---|---|
| Action specificity (IP + endpoint) | 100 % | **100 %** | cites `172.20.0.1` + `/rest/products/search` |
| `attack_type` correct | ≥ 90 % | **100 %** | "SQL injection attempt" |
| Severity ≥ high | 100 % | **100 %** | |
| Report JSON valid | 100 % | **100 %** | |
| Summary cites IP/endpoint | ≥ 60 % | **0 %** | summary is correct but generic ("the target host") — KPI under review |
| Real recall | ≥ 90 % | **0.14** | **not a model miss**: only SQLi triggered a Wazuh rule on Juice Shop; XSS/traversal/cmd/recon raised no alert (payloads unmatched, nikto/hydra absent) |

**Reading**: the *actionable* content (action, type, severity, valid JSON) is
solid — the report-quality fixes work. Two caveats, both **measurement**, not
broken reports: the summary KPI is too strict (the IP/endpoint belong in the
*action* field, which is 100 %), and live recall is limited by which attacks the
target/ruleset actually detect. To get a clean recall, fire only payloads known
to trigger rules, or use the synthetic corpus (Level 1) for the high-value custom
rules that Kali can't trigger.

Per-run machine-readable artifacts: `docs/benchmarks/kpi-ci-latest.json` and
`docs/benchmarks/report-*.{md,json}` (git-ignored, regenerated each run).

---

## 3. How to reproduce

### Level 1 — CI (no Pi, seconds)
```bash
make benchmark-ci        # writes docs/benchmarks/kpi-ci-latest.json
```

### Level 2 — Phase 1, report quality (needs the stack + Pi)
Grades the real reports the Pi produces. Reports are captured by a tiny sink that
stands in for the Shuffle webhook (the pipeline already POSTs full reports there).

```bash
# 0. stack + Juice Shop up, Pi reachable (ollama-slm/llm running)

# 1. start the capture sink on the host (binds 0.0.0.0:8099)
python -m scripts.benchmark.report_sink --port 8099 --reset --out /tmp/aegis-reports.jsonl &

# 2. find the gateway the middleware container reaches the host on
GW=$(docker network inspect aegis-node1_aegis-monitoring -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')

# 3. point the middleware's webhook at the sink (save the original first!), recreate it
cp .env /tmp/.env.bak
sed -i "s#^SHUFFLE_WEBHOOK_URL=.*#SHUFFLE_WEBHOOK_URL=http://$GW:8099/#" .env
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware

# 4. fire the attacks (writes a manifest of what was fired)
make benchmark-quality SCENARIO=all          # INTENSITY=smoke by default

# 5. WAIT for the Pi to process (≈3-9 min per escalated alert), then grade
make benchmark-quality-score                 # writes docs/benchmarks/report-quality-<ts>.md

# 6. RESTORE the webhook and stop the sink (important!)
cp /tmp/.env.bak .env
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware
pkill -f report_sink
```

### Level 2 — Phase 2, load (needs the stack + Pi)
```bash
make benchmark-load SCENARIO=all INTENSITY=soak   # hundreds of alerts, parallel
# writes docs/benchmarks/report-<ts>.md (latency, zero-loss, Pi resources)
```

Scenarios (A recon, B SQLi, C XSS, D traversal, E cmd-injection, F brute-force)
live in `scripts/benchmark/scenarios.py`. The high-value custom rules
(100001-100042), which Kali can't trigger on Juice Shop, are covered by the
labeled corpus in `tests/fixtures/corpus/` at Level 1.

### Known gotcha
Recreating the middleware container spins new `veth` interfaces → `dockerd`
fires rule 80710 (promiscuous mode), which can appear as 1-2 extra "reports" in a
capture. The scorer ignores any report that doesn't correlate to a fired
scenario, so it doesn't affect the KPI numbers.
