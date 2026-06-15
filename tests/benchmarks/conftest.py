"""Fixtures for the Level-1 KPI benchmarks.

The ``kpi_sink`` session fixture collects each test's KPI block and writes a
single artifact (``docs/benchmarks/kpi-ci-latest.json``) at session end, so a
``make benchmark-ci`` run leaves a machine-readable KPI snapshot.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

_ARTIFACT = (
    pathlib.Path(__file__).resolve().parents[2] / "docs" / "benchmarks" / "kpi-ci-latest.json"
)


@pytest.fixture(scope="session")
def kpi_sink() -> Iterator[dict[str, Any]]:
    sink: dict[str, Any] = {}
    yield sink
    _ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    _ARTIFACT.write_text(json.dumps(sink, indent=2, sort_keys=True) + "\n", encoding="utf-8")
