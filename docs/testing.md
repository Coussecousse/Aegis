# AEGIS — Testing

Three layers, each answering a different question. All run locally; only the live
KPI runs need the Pi.

| Layer | Location | Question it answers | Needs |
|---|---|---|---|
| **Unit** | `tests/unit/` | Does each piece of logic behave? (pure functions, clients, parsing) | nothing |
| **Integration** | `tests/integration/` | Do the pieces wire together correctly? (full pipeline with fakes) | nothing |
| **Benchmarks / KPIs** | `tests/benchmarks/` | Do we hit our quality targets, as measurable rates? | nothing (Level 1) / Pi (Level 2) |

## Running

```bash
make test            # unit + integration with coverage (excludes the benchmark marker)
make test-critical   # only the critical-path tests
make benchmark-ci    # the deterministic KPI suite → docs/benchmarks/kpi-ci-latest.json
```

Benchmarks are marked `@pytest.mark.benchmark` and **excluded from the default run**
(`-m 'not benchmark'`). Run them explicitly:

```bash
.venv/bin/pytest -m benchmark                       # all KPIs
.venv/bin/pytest -m "benchmark or not benchmark"    # everything
```

## What the benchmark suite contains

| File | Measures |
|---|---|
| `test_report_quality_kpis.py` | Report shape, action specificity, severity on the labeled corpus (fake model). |
| `test_fp_kpis.py` | False-positive rate with/without the noise filter. |
| `test_ueba_kpis.py` | UEBA gate decision matrix. |
| `test_connector_kpis.py` | Identity connector: fallback, idempotence. |
| `test_ueba_population_kpis.py` | Sync coverage, tier correctness, identity-attack detection (rates over a population). |
| `test_anomaly_kpis.py` | Gap 2 behavioral score: rise, decay, bounds. |
| `test_score_phase1.py` | Unit tests for the live Phase-1 scorer. |

These are **Level 1** (deterministic): a fake Ollama replays canonical responses, so a
failure is a *code* bug, not model variance. **Level 2** (live, on the Pi) replays real
attacks and grades the real model's output — see [benchmarks/README.md](benchmarks/README.md).

## The corpus

`tests/fixtures/corpus/alerts.json` + `labels.json` — a labeled set of Wazuh alerts
(attacks A–F + custom rules J-100xxx, plus benign noise) used to compute the Level-1
KPIs over a fixed population.

## Quality gate (before every commit)

```bash
.venv/bin/ruff check src/ tests/
.venv/bin/ruff format --check src/ tests/
.venv/bin/mypy src/
.venv/bin/pytest
.venv/bin/pre-commit run --all-files
```
