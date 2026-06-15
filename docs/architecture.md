# AEGIS — Repository Architecture

A map of the repo: what each area is for, and where to look when you change something.
For the runtime data flow see [middleware.md](middleware.md); for the identity/behavior
layer see [ueba.md](ueba.md).

## Two nodes

- **Node 1 (controller VM)** — all Docker services: Wazuh, RabbitMQ, ChromaDB,
  the Python middleware + collector, Shuffle SOAR, Prometheus/Grafana.
- **Node 2 (Raspberry Pi)** — Ollama only (two instances: SLM triage + LLM reports).
  Setup: [raspberrypi-ollama-setup.md](raspberrypi-ollama-setup.md).

## Source tree (`src/aegis/`)

| Path | Responsibility |
|---|---|
| `collectors/wazuh_forwarder.py` | Parse Wazuh alerts → `WazuhLog`, publish to RabbitMQ. Extracts the attacker IP (`data.srcip`) distinct from the monitored host (`agent.ip`). |
| `collectors/__main__.py` | Collector entrypoint: one-shot integration mode + `alerts.json` polling daemon. |
| `middleware/message_consumer.py` | Generic RabbitMQ consumer: connection, prefetch, reconnect, ack/nack policy, **persistent** publish. One deep module behind every stage. |
| `middleware/consumer.py` | Triage stage processor (`aegis.triage`): SLM + RAG + gates; publishes escalations; triggers identity sync on unprofiled assets. |
| `middleware/consumer_analysis.py` | Analysis stage processor (`aegis.reports`): LLM + risk + report + SOAR. |
| `middleware/consumer_identity.py` | Identity-sync worker (`identity.sync`): pulls an asset's identity context into ChromaDB. |
| `middleware/pipeline.py` | The two pipeline stages: `triage_log()` and `analyze_log()`. Gates, behavioral recording, risk, decision. |
| `middleware/prompt_builder.py` | Builds the SLM and LLM prompts (data-only; role/schema live in the Modelfiles). |
| `middleware/risk_scorer.py` | Composite `danger_score` (SLM/LLM/rule weights × criticality multiplier × UEBA factor) + uncertainty. |
| `middleware/models.py` | Pydantic models: `WazuhLog`, `SlmResponse`, `LlmResponse`, `RagContext`, `UEBAMetrics`, `RiskScore`, `Decision`, `AegisReport`, `EscalatedAlert`. |
| `rag/client.py` | ChromaDB client: asset context lookup, identity sync, and **behavioral** `record_activity`. |
| `rag/ueba.py` | Pure behavioral scoring (sliding window + EWMA baseline) — the Gap 2 anomaly engine. |
| `rag/ldap.py` | `LdapConnector` (AD-aware) implementing the `BaseIdentityConnector` seam. |
| `rag/base.py` | `BaseIdentityConnector` — the pluggable identity-store seam (LDAP today, AD/Okta tomorrow). |
| `soar/client.py` | Shuffle webhook client (async, retry). |
| `vault/client.py`, `vault/loader.py` | HashiCorp Vault KV v2 client + startup secret loader. |
| `monitoring/metrics.py` | Prometheus counters/histograms/gauges. |
| `config.py` | Typed `Settings` from env (thresholds, model names, URLs). |
| `__main__.py` | App entrypoint: load Vault secrets, start metrics, run the consumers. |

## Infrastructure (`docker/node1/`)

| Path | Responsibility |
|---|---|
| `docker-compose.yml` | Main stack (Wazuh, RabbitMQ, ChromaDB, middleware, collector, monitoring, Shuffle). |
| `docker-compose.poc.yml` | POC OpenLDAP overlay (identity source for the demo). |
| `docker-compose.juiceshop.yml` | Juice Shop + nginx — the realistic attack target. |
| `rabbitmq/config/definitions.json` | Queues/exchanges/bindings: TTLs, dead-letter wiring (see the reliability section of the POC runbook). |
| `wazuh/config/local_rules.xml` | Custom Wazuh rules (IDs 100001–100042). |
| `grafana/`, `prometheus/` | Dashboards + scrape config. |
| `middleware/Dockerfile` | Image for both the middleware and the collector. |

## Tests (`tests/`)

`unit/` (pure logic), `integration/` (pipeline wiring), `benchmarks/` (KPI harness,
marker `benchmark`), `fixtures/corpus/` (labeled alert corpus). See [testing.md](testing.md).

## Docs (`docs/`)

| Path | Topic |
|---|---|
| [architecture.md](architecture.md) | This file. |
| [middleware.md](middleware.md) | Runtime pipeline + components. |
| [ueba.md](ueba.md) | Identity store, gate, behavioral scoring. |
| [testing.md](testing.md) | Test layout + how to run. |
| [benchmarks/README.md](benchmarks/README.md) | KPIs (targets, results, reproduce). |
| [runbooks/poc-linux-startup.md](runbooks/poc-linux-startup.md) | End-to-end POC startup (Juice Shop, Kali, Shuffle). |
| [raspberrypi-ollama-setup.md](raspberrypi-ollama-setup.md) | Node 2 (Pi + Ollama) setup. |
| [runbooks/wazuh-rules.md](runbooks/wazuh-rules.md) | Custom Wazuh rule reference. |
| `adr/` | Architecture Decision Records. |
| `modelfiles/` | Ollama Modelfiles for the Pi. |
