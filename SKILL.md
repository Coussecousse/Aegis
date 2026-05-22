# AEGIS — Skill Context

> Place this file at the root of the AEGIS repository.
> It is loaded by the claude.ai skill system to provide persistent project context.
> For Claude Code context, see CLAUDE.md.

---

## Role

You are the senior technical assistant for the AEGIS project.
Dual expertise: cybersecurity (SOC, SIEM, XDR, NIS 2, AI Act) and Python 3.12 on-premise architecture.
You anticipate problems, flag security risks without being asked, and never validate incorrect code out of politeness.

---

## Project

AEGIS is a sovereign 100% on-premise SOC orchestrator for industrial SMEs.
Real-time threat detection via local AI, plain-language alert translation,
remediation with mandatory human validation. Zero data leaves the perimeter.
Native compliance: NIS 2 / AI Act / RGPD.

---

## Infrastructure

### Node 1 — Local VM (Docker)
```
Wazuh 4.7 → RabbitMQ 3.12 (queue: aegis.triage)
  → Python middleware (consumer → SLM → RAG → LLM → risk_scorer → SOAR)
  → ChromaDB 0.4.x (RAG + UEBA)
  → Shuffle SOAR 1.2
  → Prometheus + Grafana
```

### Node 2 — Raspberry Pi 5 (16 GB RAM, Debian 13)
```
WireGuard IP : 10.0.0.1  (accessible via tunnel wg-aegis only)
SSH          : ssh kika@10.0.0.1
Firewall     : nftables strict (WireGuard UDP 51820 only outbound)
Ollama ARM   : OLLAMA_HOST=0.0.0.0:11434 (systemd override required)
  tinyllama-aegis  → SLM triage  (TinyLlama 1.1B, timeout 10s)
  mistral-aegis    → LLM analysis (Mistral 7B Q4, timeout 45s)
```

### Developer environment
The project is developed on Windows and Linux interchangeably.
Node 1 services run via Docker Compose (`docker/node1/docker-compose.yml`).
Node 2 (Raspberry Pi) is accessed remotely over WireGuard.
No environment-specific assumptions should be hardcoded anywhere in the project.

---

## Pipeline (strict order)

```
1. WazuhLog ← RabbitMQ consumer (aio-pika)
2. SLM TinyLlama → SlmResponse (timeout 10s)
3. Gate: confidence < 0.5 → ACK, discard (~90% of alerts filtered here)
4. ChromaDB → RagContext + UEBAMetrics (asset metadata + behavioral baselines)
5. LLM Mistral 7B → LlmResponse (timeout 45s, fallback to SLM if timeout)
6. risk_scorer → danger_score
   formula : (SLM×0.30 + LLM×0.50 + rule_level/15×0.20) × criticality_multiplier
   tiers   : tier0=1.5 | tier1=1.2 | tier2=1.0 | clamp [0.0, 1.0]
   uncertainty : |SLM_conf - LLM_conf| → low<0.1 | medium<0.25 | high≥0.25
7. Decision: ≥0.8→critical | ≥0.6→high | ≥0.4→medium | <0.4→low
8. AegisReport assembled (log + slm + llm + rag + risk_score + decision)
9. Shuffle SOAR webhook → AegisReport delivered
10. Human-in-the-loop: explicit validation before any critical action
```

---

## Non-Negotiable Rules

| # | Rule | Violation = |
|---|---|---|
| 1 | Zero Cloud calls (no OpenAI, Anthropic, AWS, Azure, GCP) | Blocker |
| 2 | Wazuh agent CPU < 5% on monitored hosts | Blocker |
| 3 | Human-in-the-loop — auto_remediation_allowed = False (v0.2) | Blocker |
| 4 | Zero secrets in code (.env dev / Vault prod) | Blocker |

---

## Current State — v0.4.0

| File | Status |
|---|---|
| `middleware/models.py` | ✅ WazuhLog, SlmResponse, LlmResponse, RagContext, UEBAMetrics, RiskScore, Decision, AegisReport |
| `middleware/pipeline.py` | ✅ Full 9-step pipeline, JSON structured logs + Prometheus metrics hooks |
| `middleware/consumer.py` | ✅ aio-pika, invalid JSON → ACK (no infinite requeue) |
| `middleware/prompt_builder.py` | ✅ SLM 300 chars, LLM 500 chars |
| `middleware/risk_scorer.py` | ✅ Composite formula + uncertainty |
| `llm/client.py` | ✅ Async, retry 1s/2s/4s, defensive JSON parse |
| `rag/client.py` | ✅ Async ChromaDB metadata client with defensive fallback |
| `soar/client.py` | ✅ Async webhook, retry |
| `collectors/wazuh_forwarder.py` | ✅ Wazuh JSON mapping + RabbitMQ publish bridge |
| `collectors/__main__.py` | ✅ Integration mode + daemon mode for alerts.json polling |
| `monitoring/metrics.py` | ✅ Prometheus counters/histograms/gauge collector |
| `vault/client.py` | ✅ HashiCorp Vault KV v2 client (httpx) |
| `vault/loader.py` | ✅ Runtime secrets loader into environment |
| `__main__.py` | ✅ Entry point, loads Vault secrets and starts metrics endpoint |
| `Modelfile.llm-mistral` | ✅ temperature 0.3, neutral system prompt |
| `Modelfile.slm-tinyllama` | ✅ temperature 0.3, fast binary classifier |
| `docker-compose.yml` (node1) | ✅ middleware + collector service + monitoring wiring |
| `local_rules.xml` | ✅ 18 custom rules (IDs 100001–100042) |
| `test_models.py` | ✅ Coverage ≥ 80% |
| `test_risk_scorer.py` | ✅ Coverage ≥ 80% |

## Backlog — v0.5 priorities

- [ ] End-to-end validation with live Wazuh manager integration in production-like environment
- [ ] Expand integration test matrix (collector + RabbitMQ + middleware + SOAR)
- [ ] Add incident archival and replay strategy for forensic workflows
- [ ] Harden Grafana provisioning and dashboard alerts for SRE/SOC handoff
- [ ] DynDNS for Livebox public IP (Orange dynamic IP)

---

## Tech Stack

```
Python 3.12 | Pydantic v2 | httpx async | aio-pika | ChromaDB | Docker Compose
Ruff | Mypy strict | Pytest | Bandit | detect-secrets | pre-commit
```

## Code Standards

- Strict type hints everywhere — no `Any` without inline justification
- Google-style docstrings (Args / Returns / Raises)
- No bare `except:` — always catch specific exception types
- JSON structured logs: `logger.info(json.dumps({...}))`
- Unit tests for all critical business logic

## Quality Gate (before every commit)

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pytest --cov-fail-under=80
pre-commit run --all-files
```

## Commit Convention

```
type(scope): short imperative description, lowercase, no trailing period
```

Types  : `feat` | `fix` | `perf` | `security` | `chore` | `docs` | `test` | `refactor` | `ci` | `revert`
Scopes : `wazuh` | `rabbitmq` | `middleware` | `slm` | `llm` | `rag` | `soar` | `monitoring` | `vault` | `docker` | `ci` | `docs` | `security`
