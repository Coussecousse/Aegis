"""Unit tests for Prometheus metrics collector."""

from __future__ import annotations

from prometheus_client import CollectorRegistry

from aegis.monitoring.metrics import MetricsCollector


def _sample_value(
    collector: object,
    sample_name: str,
    expected_labels: dict[str, str],
) -> float:
    for metric in collector.collect():
        for sample in metric.samples:
            if sample.name == sample_name and sample.labels == expected_labels:
                return float(sample.value)
    raise AssertionError(f"Sample not found: {sample_name} labels={expected_labels}")


def test_record_alert_increments_counter() -> None:
    registry = CollectorRegistry()
    metrics = MetricsCollector(registry=registry)

    metrics.record_alert(status="processed", severity="high", duration_s=1.2)

    value = _sample_value(
        metrics.alerts_processed,
        "aegis_alerts_processed_total",
        {"status": "processed", "severity": "high"},
    )
    assert value == 1.0


def test_pipeline_duration_histogram_records_observation() -> None:
    registry = CollectorRegistry()
    metrics = MetricsCollector(registry=registry)

    metrics.record_llm(duration_s=0.42)

    count_value = _sample_value(
        metrics.pipeline_duration,
        "aegis_pipeline_duration_seconds_count",
        {"stage": "llm"},
    )
    assert count_value == 1.0


def test_pipeline_duration_buckets_cover_llm_scale_durations() -> None:
    registry = CollectorRegistry()
    metrics = MetricsCollector(registry=registry)

    metrics.record_llm(duration_s=700.0)

    bucket_10s = _sample_value(
        metrics.pipeline_duration,
        "aegis_pipeline_duration_seconds_bucket",
        {"stage": "llm", "le": "10.0"},
    )
    bucket_900s = _sample_value(
        metrics.pipeline_duration,
        "aegis_pipeline_duration_seconds_bucket",
        {"stage": "llm", "le": "900.0"},
    )

    assert bucket_10s == 0.0
    assert bucket_900s == 1.0


def test_record_triage_observes_triage_stage() -> None:
    registry = CollectorRegistry()
    metrics = MetricsCollector(registry=registry)

    metrics.record_triage(duration_s=2.5)

    count_value = _sample_value(
        metrics.pipeline_duration,
        "aegis_pipeline_duration_seconds_count",
        {"stage": "triage"},
    )
    assert count_value == 1.0


def test_danger_score_gauge_reflects_latest() -> None:
    registry = CollectorRegistry()
    metrics = MetricsCollector(registry=registry)

    metrics.record_danger_score(score=0.87, criticality="tier0")

    value = _sample_value(
        metrics.danger_score,
        "aegis_danger_score",
        {"asset_criticality": "tier0"},
    )
    assert value == 0.87
