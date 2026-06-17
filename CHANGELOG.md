# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-16

First stable release. AEGIS is a sovereign, 100% on-premise SOC orchestrator:
Wazuh → RabbitMQ → local SLM triage → ChromaDB/UEBA context → local LLM report →
Shuffle SOAR, with mandatory human validation and zero cloud calls. Highlights across
the 0.4–0.6 line: the Wazuh→RabbitMQ collector, Prometheus/Grafana observability and
Vault secrets (0.4); behavioral UEBA, zero-loss reliability and LLM-authored actions
(0.5); human pre-approved SOAR response policies (0.6). See the entries below.

## [0.6.0] - 2026-06-16

### Added

- SOAR pre-approved response policies (middleware side): a human-maintained
  `rule_id → containment action` map with an `auto` flag, loaded from
  `RESPONSE_POLICY_FILE` (empty by default). When an alert's Wazuh rule matches, the
  report's `decision.applied_response` records the action (tied to the rule code, not
  the LLM); an `auto` policy sets `auto_remediation_allowed` while keeping
  `requires_human_validation` True. Shuffle executes the containment.

## [0.5.0] - 2026-06-16

### Added

- Behavioral UEBA anomaly score (Gap 2): trailing event window + EWMA baseline
  (`rag/ueba.py`), recorded per alert via `ChromaDBClient.record_activity` and fed
  into the risk `ueba_factor`. Privilege (asset tier) is decoupled from behaviour.
- The local LLM now authors `recommended_action` itself (naming the attacker IP and
  endpoint); the deterministic remediation playbook is removed.
- Measurable, population-based UEBA KPIs (sync coverage, tier correctness,
  identity-attack detection) and behavioral-score KPIs (rise / decay / bounds);
  live Phase-2 Kali load benchmark.
- Documentation hub: `architecture`, `middleware`, `ueba`, `wazuh-alerts`,
  `soar-response-actions`, `testing`, `getting-started`, `makefile` docs; lean README.

### Changed

- Triage hardening: the UEBA false-positive gate no longer silences a confident SLM
  suspicion (`FP_GATE_CONFIDENCE_CEILING`); the SLM evaluates web-attack content from
  rule level 6 up.
- A confirmed attack raises (never lowers) the composite severity floor.
- RabbitMQ reliability: durable queues, persistent messages, a 1 h TTL and a
  dead-letter exchange to `aegis.deadletter` — nothing is silently dropped under
  overload (it is parked for human review).

### Fixed

- Silent alert loss under backlog (the reports queue had a 10-min TTL and no
  dead-letter, so escalations expired unseen on a slow inference node).
- `make docker-clean` / `docker-down` now tear down the Shuffle profile, making
  `make docker-clean && make docker-up-full` a clean, repeatable cold boot.

### Removed

- Dead code (unused RAG client methods), obsolete Modelfiles (TinyLlama, Qwen-7B
  report model), the Windows `.ps1` helper, and the ADRs (superseded by the topic docs).

## [0.4.0] - 2026-05-22

### Added

- Wazuh collector bridge to RabbitMQ (`aegis.collectors` daemon + integration mode).
- Prometheus metrics instrumentation and Grafana dashboard provisioning.
- HashiCorp Vault KV v2 client and startup secret loader.
- Shuffle triage playbook template for the human-in-the-loop workflow.

## [0.3.0] - 2026-05-21

### Added

- Release v0.3.0: runtime hardening for middleware Docker build, logging,
  RabbitMQ credential encoding, and ChromaDB client compatibility.

### Fixed

- Middleware Docker image now installs the build toolchain needed for Python
  packages with native extensions.
- Logging setup now clears duplicate handlers and writes to the configured
  `LOG_FILE` path when present.
- RabbitMQ credentials are URL-encoded before building the AMQP connection URL.
- ChromaDB client now tolerates both async and sync HTTP client variants.

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
