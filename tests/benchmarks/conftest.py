"""Fixtures for the Level-1 KPI benchmarks.

The ``kpi_sink`` session fixture collects each test's KPI block and writes a
single artifact (``docs/benchmarks/kpi-ci-latest.json``) at session end, so a
``make benchmark-ci`` run leaves a machine-readable KPI snapshot.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections.abc import Iterator
from typing import Any

import pytest

# Make the repo root importable so benchmark tests can import the (uninstalled)
# `scripts.benchmark` harness package.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_ARTIFACT = _REPO_ROOT / "docs" / "benchmarks" / "kpi-ci-latest.json"


@pytest.fixture(scope="session")
def kpi_sink() -> Iterator[dict[str, Any]]:
    sink: dict[str, Any] = {}
    yield sink
    _ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    _ARTIFACT.write_text(json.dumps(sink, indent=2, sort_keys=True) + "\n", encoding="utf-8")
