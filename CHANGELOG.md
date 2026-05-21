# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-03

### Added

- Node 1 Docker Compose stack with 11 containerised services: Wazuh Indexer,
  Wazuh Manager, Wazuh Dashboard, RabbitMQ, ChromaDB, Shuffle SOAR, Prometheus,
  Grafana, HashiCorp Vault.
- Wazuh Dashboard service with SSL and environment-based credentials
  (`WAZUH_DASHBOARD_PASSWORD`).
- 18 custom Wazuh detection rules covering 5 threat categories: lateral
  movement, ransomware staging, data exfiltration, insider threats, supply chain
  compromise (rule IDs 100001–100042, `docker/node1/wazuh/config/local_rules.xml`).
- SOC operator runbook for Wazuh custom rules,
  `docs/runbooks/wazuh-rules.md`).
- ADR-001: decision record documenting why Wazuh rules are versioned in Git
  rather than edited through the UI (`docs/adr/001-wazuh-custom-rules-versioned.md`).
- Makefile with developer task shortcuts: `lint`, `format`, `format-fix`,
  `typecheck`, `test`, `test-critical`, `security-scan`, `pre-commit-all`,
  `clean`, and `docker-*` targets.
- Developer setup guide, Makefile reference table, and infrastructure overview
  in `README.md`.
- Working Style section in `CLAUDE.md` (one-file-at-a-time discipline).
- `.gitattributes` for consistent language detection on GitHub.

### Changed

- CI workflow tolerates empty test collection and skips the coverage gate at
  scaffold stage (no false failures before tests exist).
- Dev dependency versions updated: `pytest` 8.3.3 → 9.0.3,
  `pytest-asyncio` 0.24.0 → 1.3.0.

### Fixed

- GitHub Actions upgraded to Node.js 24 compatible versions:
  `actions/checkout@v4`, `actions/setup-python@v5`.
- RabbitMQ plugin mount path and ChromaDB / Wazuh healthcheck commands.
- Wazuh and Shuffle SOAR port exposure via the `aegis-monitoring` Docker network.
- Invalid `actions/upload-artifact` reference in CI workflow.
- Security vulnerability reporting contact email in `SECURITY.md`.

### Security

- Resolved `pip-audit` failure caused by a known vulnerability in `pytest` 8.3.3.

## [0.1.0] - 2026-04-29

### Added

- Initial project scaffold
- CI pipeline
- Pre-commit hooks
- Contribution guidelines
