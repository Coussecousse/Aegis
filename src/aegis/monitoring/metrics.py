"""Prometheus metrics helpers for AEGIS pipeline observability."""

from __future__ import annotations

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram


class MetricsCollector:
    """Wrapper around AEGIS Prometheus metrics instruments."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        """Create metrics instruments and bind them to a registry.

        Args:
            registry: Optional Prometheus collector registry.
        """
        self._registry = registry or REGISTRY
        self.alerts_processed = Counter(
            "aegis_alerts_processed_total",
            "Total alerts processed by AEGIS pipeline",
            labelnames=("status", "severity"),
            registry=self._registry,
        )
        self.soar_deliveries = Counter(
            "aegis_soar_deliveries_total",
            "Total report delivery attempts to SOAR",
            labelnames=("status",),
            registry=self._registry,
        )
        self.pipeline_duration = Histogram(
            "aegis_pipeline_duration_seconds",
            "Pipeline and stage durations in seconds",
            labelnames=("stage",),
            # Default buckets top out at 10s (web-latency scale). The "llm" and
            # "total" stages routinely take minutes (Mistral 7B inference on
            # constrained hardware) — every observation would otherwise land in
            # the +Inf bucket, and histogram_quantile would report that bucket's
            # lower edge (10) as a false ceiling instead of the real percentile.
            buckets=(0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 900, 1200),
            registry=self._registry,
        )
        self.danger_score = Gauge(
            "aegis_danger_score",
            "Latest computed danger score by asset criticality",
            labelnames=("asset_criticality",),
            registry=self._registry,
        )

    def record_alert(self, status: str, severity: str, duration_s: float) -> None:
        """Record one processed alert and end-to-end duration."""
        self.alerts_processed.labels(status=status, severity=severity).inc()
        self.pipeline_duration.labels(stage="total").observe(duration_s)

    def record_slm(self, duration_s: float) -> None:
        """Record SLM stage duration."""
        self.pipeline_duration.labels(stage="slm").observe(duration_s)

    def record_rag(self, duration_s: float) -> None:
        """Record RAG stage duration."""
        self.pipeline_duration.labels(stage="rag").observe(duration_s)

    def record_llm(self, duration_s: float) -> None:
        """Record LLM stage duration."""
        self.pipeline_duration.labels(stage="llm").observe(duration_s)

    def record_soar(self, status: str) -> None:
        """Record SOAR delivery status."""
        self.soar_deliveries.labels(status=status).inc()

    def record_danger_score(self, score: float, criticality: str) -> None:
        """Set latest danger score for an asset criticality tier."""
        self.danger_score.labels(asset_criticality=criticality).set(score)
