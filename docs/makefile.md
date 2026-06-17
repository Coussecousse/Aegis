# AEGIS — Make Targets

Every workflow has a `make` target. Run `make help` for the live list (it is
generated from the `##` comments in the `Makefile`). The Makefile auto-selects
`.env` when present, else `.env.example`, and the right venv path per OS.

## Development

| Target | What it does |
|---|---|
| `make install` | Create `.venv` and install the project with dev extras. |
| `make lint` | Ruff linter (`src/ tests/`). |
| `make format` | Ruff format check (no changes). |
| `make format-fix` | Ruff format with auto-fix. |
| `make typecheck` | Mypy strict on `src/`. |
| `make test` | Full test suite with coverage gate (excludes `benchmark`). |
| `make test-critical` | Only `@pytest.mark.critical` tests. |
| `make security-scan` | Bandit + pip-audit. |
| `make pre-commit-all` | Run all pre-commit hooks on all files. |
| `make clean` | Remove caches and coverage artifacts. |

## KPIs / benchmarks

| Target | What it does |
|---|---|
| `make benchmark-ci` | Level-1 deterministic KPIs (no Pi) → `docs/benchmarks/kpi-ci-latest.json`. |
| `make benchmark` | Live KPI run (needs stack + Pi). `SCENARIO=all INTENSITY=standard`. |
| `make benchmark-quality` | Phase 1: fire corpus attacks for quality scoring (needs the report sink). |
| `make benchmark-quality-score` | Phase 1: grade captured reports vs the corpus. |
| `make benchmark-load` | Phase 2: soak load + zero-loss + resource KPIs (needs stack + Pi). |

Override scenarios/intensity, e.g. `make benchmark SCENARIO=B,C,D INTENSITY=smoke`.
Details: [benchmarks/README.md](benchmarks/README.md).

## Docker — Node 1 stack

| Target | What it does |
|---|---|
| `make docker-check` | Validate the compose config. |
| `make docker-build` | Build the middleware + collector images (first run / after code changes). |
| `make docker-up` (`docker-up-core`) | Start the core stack (no Shuffle). |
| `make docker-up-full` | Start the full stack incl. Shuffle SOAR. |
| `make docker-ps` | Show service status. |
| `make docker-logs` | Follow logs (all services). |
| `make docker-down` | Stop the stack. |
| `make docker-clean` | Stop and remove volumes (needed if passwords change). |
| `make docker-restart` | Stop then start the stack. |
| `make docker-pull` / `docker-pull-full` | Pull images (core / full). |
| `make docker-poc-up` / `docker-poc-down` | POC OpenLDAP overlay (identity source). |
| `make docker-juiceshop-up` / `docker-juiceshop-down` | Juice Shop + nginx attack target (`:9080`). |

See [getting-started.md](getting-started.md) for the order to run these in.
