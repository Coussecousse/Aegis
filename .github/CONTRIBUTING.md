# Contributing to AEGIS

Thank you for your interest in contributing to AEGIS. This document explains the process for
submitting changes, the standards we enforce, and what reviewers will check before merging.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Branch Strategy](#branch-strategy)
4. [Commit Format](#commit-format)
5. [Development Workflow](#development-workflow)
6. [Tests Required](#tests-required)
7. [Pull Request Process](#pull-request-process)
8. [Non-Negotiable Constraints](#non-negotiable-constraints)

---

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). By participating you
agree to abide by its terms.

---

## Getting Started

### Prerequisites

- Python 3.12
- Docker Engine (for integration tests)
- `pre-commit` installed globally (`pip install pre-commit`)
- A local `.env` file copied from `.env.example` with real dev values

### Local Setup

```bash
# 1. Fork and clone
git clone https://github.com/<your-fork>/aegis.git
cd aegis

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install the project and dev dependencies
pip install -e ".[dev]"

# 4. Install pre-commit hooks
pre-commit install --install-hooks

# 5. Copy environment template
cp .env.example .env
# Edit .env with your local dev values — never commit real secrets
```

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, always deployable. Protected — direct push forbidden. |
| `develop` | Integration branch for the next release. |
| `feat/<scope>/<short-description>` | New features. |
| `fix/<scope>/<short-description>` | Bug fixes. |
| `security/<scope>/<short-description>` | Security patches. |
| `chore/<scope>/<short-description>` | Maintenance, dependency updates. |

Branch from `develop`, target `develop` in your PR. The maintainer merges `develop` → `main`
on release.

---

## Commit Format

AEGIS uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

```
type(scope): short imperative description, lowercase, no trailing period

Optional body explaining the why, not the what.

Footer: BREAKING CHANGE: description, or Closes #123
```

**Allowed types**: `feat` | `fix` | `perf` | `security` | `chore` | `docs` | `test` |
`refactor` | `ci` | `revert`

**Allowed scopes**: `wazuh` | `rabbitmq` | `middleware` | `slm` | `llm` | `rag` | `soar` |
`monitoring` | `vault` | `docker` | `ci` | `docs` | `security`

The `commitlint` pre-commit hook enforces this format. A commit that does not conform will be
rejected locally before it reaches the remote.

---

## Development Workflow

```bash
# Run the full lint + typecheck + test suite (same as CI)
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pytest --cov=aegis --cov-report=term-missing
```

All four commands must pass before opening a PR.

---

## Tests Required

- **New feature** (`feat`): unit tests covering the happy path and at least two error paths.
  Coverage must not drop below **80 %** globally.
- **Bug fix** (`fix`): a regression test that reproduces the bug before the fix.
- **Critical paths** (no-cloud check, CPU cap enforcement, human-in-the-loop gate): **100 %**
  branch coverage is mandatory. These tests are tagged `@pytest.mark.critical` and a failing
  critical test blocks the PR regardless of overall coverage.
- Test file naming: `test_<module>_<expected_behaviour>.py`
- One primary assertion per test (Arrange / Act / Assert pattern).

---

## Pull Request Process

1. Ensure all pre-commit hooks pass (`pre-commit run --all-files`).
2. Open a PR against `develop` — never directly against `main`.
3. Fill in every section of the PR template; incomplete templates will be closed.
4. A minimum of **one approved review** from a maintainer is required.
5. The CI pipeline must be fully green (lint → typecheck → test → security scan).
6. Update `CHANGELOG.md` under `[Unreleased]` before the review is requested.
7. After merge, the CI automatically bumps the PATCH version.

---

## Non-Negotiable Constraints

These constraints apply to every contribution without exception. A PR violating any of them
will be rejected immediately:

- **Zero Cloud calls**: no network request to any external service or cloud API.
- **Wazuh CPU < 5 %**: no agent configuration change that risks exceeding this threshold.
- **Human-in-the-loop**: every critical action requires explicit human validation.
- **Zero secrets in code**: no key, token, password, or credential in any file tracked by git.
