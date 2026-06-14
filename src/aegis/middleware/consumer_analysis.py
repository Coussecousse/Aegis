"""Analysis-stage processor for the AEGIS pipeline (slow LLM + risk + SOAR).

Behind :class:`MessageConsumer` (queue ``aegis.reports``): decode an
EscalatedAlert and run :func:`analyze_log` (LLM analysis, risk scoring, report,
SOAR delivery). Runs independently of triage so a multi-minute LLM analysis
never blocks the fast SLM triage loop.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import AsyncExitStack
from typing import Any

from pydantic import ValidationError

from aegis.llm.client import OllamaClient
from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
    build_amqp_url,
)
from aegis.middleware.models import EscalatedAlert
from aegis.middleware.pipeline import analyze_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.soar.client import ShuffleClient
from aegis.vault.loader import load_secrets_to_env

logger = logging.getLogger(__name__)


class AnalysisProcessor:
    """Run LLM analysis on one escalated alert and deliver the report to SOAR."""

    def __init__(
        self,
        *,
        ollama_base_url: str = "http://10.0.0.1:11435",
        shuffle_webhook_url: str = "http://shuffle:3001/api/v1/hooks/",
        metrics: MetricsCollector | None = None,
        llm_timeout: float = 45.0,
    ) -> None:
        self.ollama_base_url = ollama_base_url
        self.shuffle_webhook_url = shuffle_webhook_url
        self.metrics = metrics
        self.llm_timeout = llm_timeout

        self._stack: AsyncExitStack | None = None
        self._ollama: OllamaClient | None = None
        self._shuffle: ShuffleClient | None = None

    async def __aenter__(self) -> AnalysisProcessor:
        stack = AsyncExitStack()
        self._ollama = await stack.enter_async_context(OllamaClient(self.ollama_base_url))
        self._shuffle = await stack.enter_async_context(ShuffleClient(self.shuffle_webhook_url))
        self._stack = stack
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        """Analyze one escalated alert (publish is unused for this stage)."""
        _ = publish
        if self._ollama is None or self._shuffle is None:
            raise RuntimeError("AnalysisProcessor used outside its context manager")

        try:
            escalated = EscalatedAlert(**payload)
        except ValidationError as exc:
            raise UnprocessableMessageError(f"invalid EscalatedAlert: {exc}") from exc

        report = await analyze_log(
            escalated=escalated,
            ollama_client=self._ollama,
            shuffle_client=self._shuffle,
            metrics=self.metrics,
            llm_timeout=self.llm_timeout,
        )

        if report is not None:
            logger.info(
                json.dumps(
                    {
                        "event": "report_generated",
                        "alert_id": str(escalated.log.id),
                        "danger_score": report.risk_score.danger_score,
                    }
                )
            )
        else:
            logger.warning(
                json.dumps(
                    {
                        "event": "report_generation_failed",
                        "alert_id": str(escalated.log.id),
                        "report_id": str(escalated.report_id),
                    }
                )
            )


def build_analysis_consumer_from_env(
    metrics: MetricsCollector | None = None,
) -> MessageConsumer:
    """Build the analysis MessageConsumer from environment variables.

    Args:
        metrics: Shared MetricsCollector instance (must be the same one passed to
            the triage consumer to avoid duplicate Prometheus registrations).
    """
    load_secrets_to_env()
    processor = AnalysisProcessor(
        ollama_base_url=os.getenv("OLLAMA_LLM_BASE_URL", "http://10.0.0.1:11435"),
        shuffle_webhook_url=os.getenv("SHUFFLE_WEBHOOK_URL", "http://shuffle:3001/api/v1/hooks/"),
        metrics=metrics,
        llm_timeout=float(os.getenv("LLM_TIMEOUT", "45.0")),
    )
    return MessageConsumer(
        amqp_url=build_amqp_url(
            os.getenv("RABBITMQ_HOST", "localhost"),
            int(os.getenv("RABBITMQ_PORT", "5672")),
            os.getenv("RABBITMQ_USER", "guest"),
            os.getenv("RABBITMQ_PASSWORD", "guest"),
            os.getenv("RABBITMQ_VHOST", "aegis"),
        ),
        queue_name=os.getenv("RABBITMQ_REPORTS_QUEUE", "aegis.reports"),
        processor=processor,
        on_error="requeue",
    )
