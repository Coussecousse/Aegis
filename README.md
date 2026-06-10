# AEGIS

Sovereign on-premise SOC orchestrator for industrial SMEs that cannot send security data to the Cloud.

[![CI](https://github.com/Coussecousse/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Coussecousse/Aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)

## What Is AEGIS

AEGIS collects security logs from machines and critical systems across your network. It analyzes
them on-premise with local AI models to detect suspicious behavior without sending data outside
your site. When activity looks like an attack, it produces a plain-language incident report and
waits for explicit human approval before any containment action is executed. It is built for
companies that must meet NIS 2 requirements but do not have a dedicated SOC team.

## How It Works

1. Wazuh agents collect logs from endpoints, Active Directory, firewall devices, and databases.
2. Logs are buffered in RabbitMQ to absorb peaks and prevent overload during an attack.
3. Qwen 2.5 1.5B (local SLM) performs first-pass triage and classifies events as normal or suspicious.
4. If suspicious: the middleware queries ChromaDB (local vector database) to retrieve the business
  context of the targeted asset — its name, role, and criticality level.
5. Mistral 7B (local LLM) combines the raw log, the asset context from ChromaDB, and the threat
  pattern to generate a plain-language incident report.
6. Shuffle SOAR presents the report to the operator for explicit validation.
7. Only after human approval, containment actions are applied (for example firewall rule updates or
  AD account lock).

## Why On-Premise

- Cloud platforms can place logs under foreign jurisdictions (including US Cloud Act), which is a
  legal risk for European industrial companies under NIS 2.
- All AI inference runs locally on a Raspberry Pi 5 with Ollama: no subscription, no external
  dependency, and no data leaving the network.

## Stack

| Layer | Component | Version |
|---|---|---|
| Language | Python | 3.12 |
| SIEM / Collection | Wazuh Manager | 4.7 |
| Message Broker | RabbitMQ | 3.12 |
| Local AI (triage) | Ollama — Qwen 2.5 | 1.5B |
| Local AI (reports) | Ollama — Mistral | 7B Q4 |
| Vector DB / RAG | ChromaDB | 0.4.x |
| SOAR | Shuffle SOAR | 1.2 |
| Search backend (dependency) | OpenSearch | via Wazuh Indexer and Shuffle datastore |
| Monitoring | Prometheus + Grafana | 2.45 / 10.4 |
| Secrets | HashiCorp Vault (on-prem) | KMS AES-256 |
| Containerisation | Docker Engine + Compose | latest stable |
| CI/CD | GitHub Actions | — |

## Infrastructure

AEGIS runs on two physical nodes:

**Node 1 — Controller VM** (standard x86 VM on company LAN)
Hosts: Wazuh Manager, RabbitMQ, ChromaDB, Shuffle SOAR,
Prometheus, Grafana. All services run in Docker on an isolated
internal network with zero outbound internet access.

**Node 2 — AI Appliance** (Raspberry Pi 5, 16 GB RAM, ARM)
Hosts: Ollama with Qwen 2.5 1.5B (triage) and Mistral 7B Q4
(incident reports). No Docker required — Ollama runs as a native
service. Node 1 reaches it via HTTP on the local network.

Docker configuration lives in `docker/node1/`.
See `docker/node2/README.md` for Node 2 setup instructions.

### Runtime Modes (Node 1)

- **Core mode (default):** Wazuh + RabbitMQ + ChromaDB + Middleware + Prometheus + Grafana.
  Shuffle services are not started.
- **Full mode:** Core mode + Shuffle SOAR backend/frontend + Shuffle datastore (OpenSearch).

OpenSearch is therefore present in two places:
- Wazuh Indexer (required by Wazuh itself)
- Shuffle datastore (required only in full mode)

## Project Status

| Version | Status | Description |
|---------|--------|-------------|
| v0.1.0 | ✅ Released | Project scaffold, CI/CD, governance |
| v0.2.0 | ✅ Released | Docker infrastructure (Node 1), Wazuh custom rules |
| v0.3.0 | ✅ Released | Middleware runtime hardening, RabbitMQ consumer, logging |
| v0.4.0 | ✅ Released | Wazuh collector bridge, Prometheus/Grafana metrics, Vault loader, Shuffle playbook |
| v1.0.0 | 📋 Planned | Full pipeline, NIS 2 audit validated |

Current branch: `develop` — active development.
Stable branch: `main` — mirrors last release tag.

## Prerequisites

- Python 3.12
- Docker Engine
- pre-commit (`pip install pre-commit`)

## Quick Start

```bash
# Clone and enter the repo
git clone https://github.com/Coussecousse/Aegis.git
cd Aegis
git checkout main

# Copy and fill in secrets
cp .env.example .env
# Edit .env with your local passwords (see .env.example for all variables)

# Build the middleware and collector images (required on first run)
make docker-build

# Start Node 1 in core mode (default, without Shuffle)
make docker-up

# Or start Node 1 in full mode (includes Shuffle + its OpenSearch datastore)
make docker-up-full

# Verify all services are healthy
make docker-ps
```

Once core services show `healthy`, the Wazuh Dashboard is available at
`https://localhost:5601` and Grafana at `http://localhost:3000`.

In full mode, Shuffle Frontend is available at `http://localhost:3001`.

> **Linux note:** `vm.max_map_count` must be ≥ 262144 for the Wazuh indexer
> (OpenSearch). Check with `cat /proc/sys/vm/max_map_count`. If lower, run
> `sudo sysctl -w vm.max_map_count=262144` (add to `/etc/sysctl.conf` to persist).

> The AI triage pipeline is production-ready in v0.4.0, with Wazuh collector
bridge, Prometheus/Grafana observability, and Vault-based secret loading.

## Developer Setup

```bash
# Clone and enter the repo
git clone https://github.com/Coussecousse/Aegis.git
cd Aegis
git checkout develop

# Install dependencies and pre-commit hooks
make install
pre-commit install --install-hooks
pre-commit install --hook-type commit-msg

# Copy environment template
cp .env.example .env
# Edit .env with your local values
```

### Common commands

| Command | Description |
|---------|-------------|
| `make lint` | Run Ruff linter |
| `make format` | Check formatting (no changes) |
| `make format-fix` | Auto-fix formatting |
| `make typecheck` | Run Mypy strict type check |
| `make test` | Run full test suite with coverage |
| `make test-critical` | Run only critical path tests |
| `make security-scan` | Run Bandit + pip-audit |
| `make pre-commit-all` | Run all hooks on all files |
| `make clean` | Remove cache directories |
| `make docker-build` | Build middleware and collector images |
| `make docker-up` | Start Node 1 in core mode (without Shuffle) |
| `make docker-up-full` | Start Node 1 in full mode (with Shuffle) |
| `make docker-pull` | Pull core-mode images |
| `make docker-pull-full` | Pull full-mode images |
| `make docker-poc-up` | Start POC OpenLDAP stack (after main stack) |
| `make docker-poc-down` | Stop POC OpenLDAP stack |

> Run `make help` for the full list.

## Contributing

Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before opening a PR.

## License

Apache 2.0 - see [LICENSE](LICENSE).
