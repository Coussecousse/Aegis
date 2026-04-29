# AEGIS

Sovereign on-premise SOC orchestrator for industrial SMEs that cannot send security data to the Cloud.

[![CI](https://github.com/aegis-project/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/aegis-project/aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)

## Why AEGIS

- Industrial SMEs face legal and operational constraints that make external cloud processing risky
  or non-compliant (Cloud Act, data sovereignty concerns).
- NIS 2 compliance requires robust detection, traceability, and controlled remediation workflows.
- Security teams in SMEs need automation assistance without losing human control over critical
  actions.

## Architecture

AEGIS orchestrates telemetry ingestion, event buffering, local AI triage/reporting, and
human-validated remediation workflows in a fully on-premise security pipeline. The target deployment
follows a two-node model: one controller VM for orchestration, SIEM, SOAR, monitoring, and secrets;
and one ARM AI appliance dedicated to local LLM inference.

## Prerequisites

- Python 3.12
- Docker Engine
- pre-commit

## Quick Start

(available from v0.2.0 once infrastructure is wired)

## Contributing

See [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md).

## License

Apache 2.0.
