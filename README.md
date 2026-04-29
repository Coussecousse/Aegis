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
3. TinyLlama (local SLM) performs first-pass triage and classifies events as normal or suspicious.
4. If suspicious, Mistral 7B (local LLM) combines logs and asset context to write a plain-language
   incident report.
5. Shuffle SOAR presents the report to an operator for explicit validation.
6. Only after human approval, containment actions are applied (for example firewall rule updates or
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
| Local AI (triage) | Ollama - TinyLlama | 1.1B |
| Local AI (reports) | Ollama - Mistral | 7B Q4 |
| Vector DB / RAG | ChromaDB | 0.4.x |
| SOAR | Shuffle SOAR | 1.2 |
| Monitoring | Prometheus + Grafana | 2.45 / 10.4 |
| Secrets | HashiCorp Vault (on-prem) | KMS AES-256 |
| Containerisation | Docker Engine + Compose | latest stable |
| CI/CD | GitHub Actions | - |

## Project Status

Current version: v0.1.0 - project scaffold only, no functional code yet.
Infrastructure wiring starts at v0.2.0.

## Prerequisites

- Python 3.12
- Docker Engine
- pre-commit (`pip install pre-commit`)

## Quick Start

(available from v0.2.0 once infrastructure is wired)

## Contributing

Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before opening a PR.

## License

Apache 2.0 - see [LICENSE](LICENSE).
