# AEGIS — Copilot Context File

> Read this file at the start of every session. Do not modify it without a deliberate architectural decision.

---

## Project Summary

AEGIS is a sovereign, 100% open-source, on-premise SOC orchestrator designed for industrial SMEs
that cannot send data to the Cloud (NIS 2, GDPR, Cloud Act constraints). It detects threats in
real time via a local AI, translates alerts into plain language, and proposes remediation actions
that require explicit human validation before execution. No data ever leaves the perimeter.

---

## Tech Stack

| Layer | Component | Version |
|---|---|---|
| Language | Python | 3.12 |
| SIEM / Collection | Wazuh Manager | 4.7 |
| Message Broker | RabbitMQ | 3.12 |
| Local AI (triage) | Ollama — Qwen 2.5 | 1.5B |
| Local AI (reports) | Ollama — Mistral | 7B Q4 |
| Vector DB / RAG | ChromaDB | 0.4.x |
| SOAR | Shuffle SOAR | 1.2 |
| Monitoring | Prometheus + Grafana | 2.45 / 10.4 |
| Secrets | HashiCorp Vault (on-prem) | KMS AES-256 |
| Containerisation | Docker Engine + Compose | latest stable |
| CI/CD | GitHub Actions | — |

---

## Non-Negotiable Rules

### 1. Zero Cloud Calls
No dependency on OpenAI, Anthropic, AWS, Azure, GCP, or any external API.
All AI inference runs exclusively through Ollama locally.
Any PR introducing an outbound network call to a cloud endpoint **must be rejected**.

### 2. Wazuh CPU < 5 %
Never propose an agent configuration that exceeds 5 % CPU usage on the monitored host.
Exceeding this threshold risks stopping industrial production. This constraint is absolute.

### 3. Human-in-the-Loop
Every critical action (server isolation, AD account revocation, firewall rule change) must wait
for explicit human validation before execution. The system proposes — the human validates.
Automated execution of critical actions without approval is a **blocker bug**.

### 4. Zero Secrets in Code
Keys, tokens, passwords, and certificates must never appear in source code or commits.
In development: use `.env` (excluded from git via `.gitignore`).
In production: all secrets are fetched from HashiCorp Vault via the Vault API.
`detect-secrets` pre-commit hook blocks any commit containing a string resembling a secret.

---

## Commit Convention (Conventional Commits)

```
type(scope): short imperative description, lowercase, no trailing period

Optional body if explanation is needed.

Footer: BREAKING CHANGE: description, or Closes #123
```

**Types**: `feat` | `fix` | `perf` | `security` | `chore` | `docs` | `test` | `refactor` | `ci` | `revert`

**Scopes**: `wazuh` | `rabbitmq` | `middleware` | `slm` | `llm` | `rag` | `soar` | `monitoring` | `vault` | `docker` | `ci` | `docs` | `security`

**Valid examples**:
```
feat(middleware): add async rabbitmq consumer with retry logic
fix(wazuh): enforce cpu cap below 5% on legacy servers
security(vault): add key rotation policy for AES-256 backups
chore(docker): pin all image versions for reproducibility
ci(github-actions): add SAST scan step before image push
```

### Commit Granularity Policy (Mandatory)

- Keep commits **small, atomic, and reviewable**.
- Default target: **1 concern per commit** (feature unit, fix unit, or test unit).
- Avoid mixing unrelated areas in one commit (e.g., middleware + docs + CI together).
- Separate commits by intent when possible:
  - code changes
  - tests
  - tooling/config
  - documentation
- If a commit touches many files, explain why in the commit body.
- Prefer a sequence of short commits over one large commit.

### Mandatory Quality Gate Before Commit/Push

Before every commit (and again before push), run and pass:

1. Ruff lint
2. Ruff format check
3. Mypy strict
4. Pytest
5. Pre-commit hooks

Preferred commands:

```bash
.venv/Scripts/ruff check src/ tests/ || .venv/bin/ruff check src/ tests/
.venv/Scripts/ruff format --check src/ tests/ || .venv/bin/ruff format --check src/ tests/
.venv/Scripts/mypy src/ || .venv/bin/mypy src/
.venv/Scripts/pytest || .venv/bin/pytest
.venv/Scripts/pre-commit run --all-files || .venv/bin/pre-commit run --all-files
```

If one step fails: do not commit/push until fixed.

---

## Python Style

- **Python 3.12** — type hints are mandatory on every function signature and class attribute
- **Docstrings**: Google style (`Args:`, `Returns:`, `Raises:`)
- **Linter / Formatter**: Ruff (replaces Black + Flake8 + isort) — config in `pyproject.toml`
- **Type checker**: Mypy in strict mode
- **Line length**: 100 characters
- **No `Any`** unless the use is justified by an inline comment explaining why
- **No bare `except:`** — always catch a specific exception type
- **No mutable default arguments** in function signatures

---

## Directory Structure

```
aegis/
├── CLAUDE.md                   # This file — Copilot context
├── README.md
├── CHANGELOG.md
├── LICENSE                     # Apache 2.0
├── pyproject.toml              # Centralised config: Ruff, Mypy, Pytest, metadata
├── .pre-commit-config.yaml
├── .editorconfig
├── .gitignore
├── .env.example
├── .github/
│   ├── CONTRIBUTING.md
│   ├── CODE_OF_CONDUCT.md
│   ├── SECURITY.md
│   ├── pull_request_template.md
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── workflows/
│       └── ci.yml
├── src/
│   └── aegis/                  # Main Python package (to be built in v0.2+)
│       ├── __init__.py
│       ├── middleware/         # Orchestration core
│       ├── collectors/         # Wazuh / log ingest adapters
│       ├── llm/                # Ollama interface (triage + reports)
│       ├── rag/                # ChromaDB interface
│       ├── soar/               # Shuffle SOAR playbook triggers
│       ├── vault/              # HashiCorp Vault client
│       └── monitoring/         # Prometheus metrics
├── tests/
│   ├── unit/
│   └── integration/
└── docs/                       # See docs/architecture.md for the full file map
    ├── architecture.md         # Repo file map (source of truth for "where is X")
    ├── middleware.md           # Pipeline, gates, risk scoring, reliability
    ├── ueba.md                 # Identity store, gate, behavioral anomaly scoring
    ├── wazuh-alerts.md         # Wazuh alert format ingested + filtering
    ├── soar-response-actions.md # Human-validated containment (Shuffle) — current + planned
    ├── testing.md              # Test layers + how to run
    ├── makefile.md             # Every make target
    ├── getting-started.md      # Setup steps + gotchas
    ├── benchmarks/README.md    # KPIs (targets, results, reproduce)
    ├── runbooks/               # poc-linux-startup.md, wazuh-rules.md
    ├── modelfiles/             # Official Ollama Modelfiles for Raspberry Pi deployment
    └── raspberrypi-ollama-setup.md  # Raspberry Pi Ollama deployment guide
```

---

## Versioning

- **Current version**: `v0.5.0`
- **Scheme**: SemVer (`MAJOR.MINOR.PATCH`)
- PATCH bump: automatic on every merged PR via CI
- MINOR bump: human decision when a new feature is complete
- **v0.4.0 release criteria (done):**
  - Wazuh collector bridge to RabbitMQ (`aegis.collectors` daemon + integration mode)
  - Prometheus metrics instrumentation + Grafana dashboard provisioning
  - Vault KV v2 client and startup secret loader integration
  - Shuffle triage playbook template for human-in-the-loop workflow
  - Unit/integration test suite passing with strict quality gate
- **v1.0.0 release criteria**:
  1. Successful NIS 2 / AI Act audit
  2. Demonstrated MTTT (Mean Time To Triage) reduction ≥ 40 % in a real environment
  3. Full test coverage on all critical paths (no-cloud check, CPU cap, human-in-the-loop gate)

---

## Working Style

When generating code or files in a session:
- Explain what you are about to generate and why before writing it (2-3 sentences).
- Generate one file at a time.
- After each file, briefly note what to verify before moving on.
- Prefer small, focused changes over large blocks. If a task requires more than
  2 files, pause and ask for confirmation before continuing.
- Never silently skip a file — if you decide not to generate something, say why.

### Documentation Freshness Check (Mandatory Before Every Commit)

Before committing any change, verify that the following are still accurate and
update them if needed — in a **separate `docs` commit** when content changes:

1. **README.md** — feature list, quickstart commands, env var table
2. **Makefile** — does a new target need adding? are existing targets still correct?
3. **`docs/runbooks/poc-linux-startup.md`** — POC steps, env var names, known issues
4. **`.env.example`** — does it list every env var now read by the code?
5. Any other doc in `docs/` that describes the changed component

If none of those need updating, explicitly confirm in the commit body:
`Docs: no update needed`.

### Default Agent Behavior (Do Not Ask Repeatedly)

Unless explicitly told otherwise in the current session, the agent must:

- enforce commit granularity policy above,
- run the full quality gate before commit/push,
- use conventional commits that are specific and short,
- avoid committing files explicitly marked as "hold" by the user,
- run the documentation freshness check before every commit.
