"""PromQL queries for the AEGIS KPI harness + a thin Prometheus client.

The latency/queue queries mirror ADR 002 and are parameterised by the run
window so the same expression works for any benchmark duration.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


def latency_quantile(stage: str, quantile: float, window: str) -> str:
    """histogram_quantile of a pipeline stage over the window."""
    return (
        f"histogram_quantile({quantile}, sum(rate("
        f'aegis_pipeline_duration_seconds_bucket{{stage="{stage}"}}[{window}])) by (le))'
    )


def queue_peak(queue: str, window: str) -> str:
    """Peak depth of a RabbitMQ queue over the window."""
    return f'max_over_time(rabbitmq_queue_messages{{queue="{queue}", vhost="aegis"}}[{window}])'


def soar_success_rate(window: str) -> str:
    """Fraction of SOAR deliveries that succeeded over the window."""
    return (
        f'sum(increase(aegis_soar_deliveries_total{{status="success"}}[{window}])) '
        f"/ clamp_min(sum(increase(aegis_soar_deliveries_total[{window}])), 1)"
    )


def alerts_by_status(window: str) -> str:
    """Processed-alert counts by status over the window."""
    return f"sum(increase(aegis_alerts_processed_total[{window}])) by (status)"


# --- Raspberry Pi resources (require node_exporter on the Pi, job-agnostic) ---


def pi_cpu_busy_pct(window: str) -> str:
    """Average CPU busy % across cores over the window (100 - idle%)."""
    return f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle"}}[{window}])) * 100)'


def pi_mem_used_pct() -> str:
    """Used memory % (1 - available/total)."""
    return "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100"


def pi_temp_celsius() -> str:
    """Max hwmon/thermal-zone temperature in °C (whichever the Pi exposes)."""
    return "max(node_hwmon_temp_celsius or node_thermal_zone_temp)"


def query_instant(prom_url: str, expr: str, at_iso: str | None = None) -> list[dict[str, Any]]:
    """Run an instant query; returns the Prometheus result vector (possibly empty)."""
    params = {"query": expr}
    if at_iso is not None:
        params["time"] = at_iso
    url = f"{prom_url.rstrip('/')}/api/v1/query?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=10) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        return []
    result: list[dict[str, Any]] = payload["data"]["result"]
    return result


def scalar(result: list[dict[str, Any]]) -> float | None:
    """Extract a single scalar value from a result vector, or None."""
    if not result:
        return None
    try:
        return float(result[0]["value"][1])
    except (KeyError, IndexError, ValueError):
        return None
