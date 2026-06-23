# AEGIS

Sovereign on-premise XDR orchestrator for industrial SMEs that cannot send security data to the Cloud.

[![CI](https://github.com/Coussecousse/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Coussecousse/Aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)

AEGIS collects security logs across your network and analyses them **on-premise** with
local AI to detect threats — **no data ever leaves the site**. When activity looks like
an attack it produces a plain-language incident report and waits for **explicit human
approval** before any containment action. It is built for companies that must meet NIS 2
without a dedicated XDR team.

- **100% local AI** — Ollama on a Raspberry Pi; no OpenAI/AWS/Azure/GCP, no subscription.
- **Sovereign** — avoids foreign jurisdiction over logs (US Cloud Act) under NIS 2 / GDPR.
- **Human-in-the-loop** — AEGIS proposes; a human validates before anything is executed.

**The pipeline:**

```
Wazuh → RabbitMQ → SLM triage → PostgreSQL/UEBA context → LLM report → Shuffle SOAR → human validation
```

Details in [docs/middleware.md](docs/middleware.md).

## Documentation

Start here — each topic has its own doc:

| Doc | What it covers |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | **Set up the project step by step + what to watch out for.** |
| [docs/architecture.md](docs/architecture.md) | Repository map — what every file/area is for. |
| [docs/middleware.md](docs/middleware.md) | The pipeline: stages, gates, risk scoring, reliability. |
| [docs/ueba.md](docs/ueba.md) | Asset context: pluggable identity store, auto-update, behavioral scoring. |
| [docs/wazuh-alerts.md](docs/wazuh-alerts.md) | The Wazuh alert format AEGIS ingests + filtering. |
| [docs/soar-response-actions.md](docs/soar-response-actions.md) | Human-validated containment in Shuffle (current + planned). |
| [docs/testing.md](docs/testing.md) | Test layers (unit / integration / KPI benchmarks). |
| [docs/benchmarks/README.md](docs/benchmarks/README.md) | KPIs: targets, measured results, reproduce. |
| [docs/makefile.md](docs/makefile.md) | Every `make` target. |
| [docs/runbooks/poc-linux-startup.md](docs/runbooks/poc-linux-startup.md) | End-to-end POC (Juice Shop, Kali, Shuffle). |
| [docs/raspberrypi-ollama-setup.md](docs/raspberrypi-ollama-setup.md) | Node 2 — Raspberry Pi + Ollama setup. |
| [docs/runbooks/wazuh-rules.md](docs/runbooks/wazuh-rules.md) | Custom Wazuh detection rules. |

## Stack

| Layer | Component |
|---|---|
| Language | Python 3.12 |
| SIEM / collection | Wazuh Manager 4.7 |
| Message broker | RabbitMQ 3.12 |
| Local AI | Ollama — Qwen 2.5 1.5B (triage) + Mistral 7B Q4 (reports) |
| Identity store | PostgreSQL 16 (asset profiles + UEBA time-series) |
| SOAR | Shuffle 1.2 |
| Monitoring | Prometheus + Grafana |
| Secrets | HashiCorp Vault |
| Runtime | Docker Engine + Compose |

AEGIS runs on **two nodes**:

- **Node 1** — controller VM: all Docker services (Wazuh, RabbitMQ, PostgreSQL, middleware, Shuffle, Prometheus/Grafana).
- **Node 2** — Raspberry Pi 5: Ollama only (SLM triage + LLM reports).

See [docs/architecture.md](docs/architecture.md).

## Quick start

```bash
cp .env.example .env      # then fill every CHANGE_ME value
make docker-build         # build middleware + collector images
make docker-up            # start Node 1 (core); or `make docker-up-full` with Shuffle
make docker-ps            # wait until services are healthy
```

- **Full setup** (Node 2, identity connector, attack target, gotchas) → [docs/getting-started.md](docs/getting-started.md)
- **All `make` targets** → [docs/makefile.md](docs/makefile.md)

## Project status

**`v1.0.0`** — first stable release.<br>
Behavioral UEBA · zero-loss reliability · LLM-authored actions · pre-approved SOAR response policies.<br>
Active branch: `develop` · stable: `main` · full history in [CHANGELOG.md](CHANGELOG.md).

## Contributing & license

Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before opening a PR.
Licensed under Apache 2.0 — see [LICENSE](LICENSE).
