# AEGIS — Middleware

The middleware is the orchestration core: it turns a raw Wazuh alert into a
validated, plain-language incident report. It is split into **two independent
stages** so a slow multi-minute LLM analysis never blocks fast triage.

```
Wazuh ──(collector)──> RabbitMQ aegis.triage
                              │
                    Stage 1: triage_log()   (fast: SLM + RAG + gates)
                              │  escalate
                              ▼
                       RabbitMQ aegis.reports
                              │
                    Stage 2: analyze_log()  (slow: LLM + risk + report + SOAR)
                              │
                              ▼
                        Shuffle SOAR  ──> human validation
```

Each stage is a thin `MessageProcessor` behind the generic
[`MessageConsumer`](../src/aegis/middleware/message_consumer.py), which owns the
RabbitMQ connection, prefetch, reconnect loop, and the single ack/nack policy.

## Stage 1 — Triage (`triage_log`, queue `aegis.triage`)

1. **SLM scoring** — Qwen 2.5 1.5B returns `is_suspect` + `confidence`. The SLM
   Modelfile evaluates rule content from **level 6 up** (web-attack signatures are
   suspect even at level 6).
2. **Suspicion gate** — `not is_suspect or confidence < SUSPICION_THRESHOLD` → discard.
3. **RAG + behavioral recording** — `record_activity()` fetches the asset context
   **and** updates its behavioral `anomaly_score` (see [ueba.md](ueba.md)).
4. **Identity self-update** — if the asset has no baseline, enqueue an `identity.sync`
   job (deduplicated) so its context is populated for next time.
5. **UEBA false-positive gate** — discard only when a real baseline says *normal*
   (low anomaly), the rule is low severity (≤ 8), the asset is non-critical, **and**
   the SLM was only weakly suspicious (confidence < `FP_GATE_CONFIDENCE_CEILING`).
   A confident suspicion is never silenced by a calm asset.

Surviving alerts are bundled into an `EscalatedAlert` and **published persistently**
to `aegis.reports`.

## Stage 2 — Analysis (`analyze_log`, queue `aegis.reports`)

1. **LLM analysis** — Mistral 7B produces `attack_type`, severity, a plain-language
   summary, and the **`recommended_action`** (the LLM authors the action itself,
   naming the attacker IP + endpoint — there is no deterministic playbook).
2. **Risk score** — composite `danger_score` (see below).
3. **Decision** — severity from `danger_score`, raised to the LLM's severity when the
   LLM **confirms** an attack (the composite is a floor). `requires_human_validation`
   is always `True`; `auto_remediation_allowed` is always `False` (v0.2 rule).
4. **Report + SOAR** — assemble the `AegisReport` and POST it to the Shuffle webhook.

## Risk scoring ([`risk_scorer.py`](../src/aegis/middleware/risk_scorer.py))

```
base   = SLM×0.30 + LLM×0.50 + (rule_level/15)×0.20
danger = clamp( base × criticality_multiplier × ueba_factor , 0, 1 )

criticality_multiplier : tier0=1.5 | tier1=1.2 | tier2=1.0   (privilege)
ueba_factor            : 0.70 + anomaly_score×0.30 (with baseline) else 1.0  (behavior)
severity               : ≥0.8 critical | ≥0.6 high | ≥0.4 medium | else low
                          (a confirmed attack may raise this, never lower it)
```

Privilege (criticality) and behavior (anomaly) are **separate** inputs — see
[ueba.md](ueba.md).

## Reliability

- Queues are **durable**, messages **persistent** → a broker restart loses nothing.
- `aegis.triage` and `aegis.reports` have a 1 h TTL + a **dead-letter exchange**:
  anything that can't be processed in time is *parked* in `aegis.deadletter`, never
  silently dropped. Details + ops commands: the *Message reliability* section of
  [poc-linux-startup.md](runbooks/poc-linux-startup.md).

## Configuration ([`config.py`](../src/aegis/config.py))

Key env vars (full list in `.env.example`): `SUSPICION_THRESHOLD`,
`FP_GATE_CONFIDENCE_CEILING`, `SLM_MODEL` / `LLM_MODEL`, `LLM_USE_SCHEMA`,
`WAZUH_MIN_LEVEL`, `SHUFFLE_WEBHOOK_URL`, RabbitMQ / ChromaDB / Ollama endpoints.
