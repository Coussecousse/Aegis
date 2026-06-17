"""Analysis-stage processor for the AEGIS pipeline (slow LLM + risk + SOAR).

Behind :class:`MessageConsumer` (queue ``aegis.reports``): decode an
EscalatedAlert and run :func:`analyze_log` (LLM analysis, risk scoring, report,
SOAR delivery). Runs independently of triage so a multi-minute LLM analysis
never blocks the fast SLM triage loop.
"""

from __future__ import annotations

import json
import logging
from contextlib import AsyncExitStack
from typing import Any

from pydantic import ValidationError

from aegis.config import Settings
from aegis.llm.client import OllamaClient
from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
)
from aegis.middleware.models import EscalatedAlert
from aegis.middleware.pipeline import analyze_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.soar.client import ShuffleClient
from aegis.soar.response_policy import load_policies

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
        llm_model: str = "mistral-aegis",
        use_schema: bool = False,
        response_policy_file: str | None = None,
    ) -> None:
        self.ollama_base_url = ollama_base_url
        self.shuffle_webhook_url = shuffle_webhook_url
        self.metrics = metrics
        self.llm_timeout = llm_timeout
        self.llm_model = llm_model
        self.use_schema = use_schema
        # Human-maintained SOAR response policies (rule_id → pre-defined action),
        # loaded once at startup; empty (no automatic action) when unconfigured.
        self.response_policies = load_policies(response_policy_file)

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
            llm_model=self.llm_model,
            use_schema=self.use_schema,
            response_policies=self.response_policies,
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


def build_analysis_consumer(
    settings: Settings, metrics: MetricsCollector | None = None
) -> MessageConsumer:
    """Build the analysis MessageConsumer from settings.

    Args:
        settings: Application settings.
        metrics: Shared MetricsCollector instance (must be the same one passed to
            the triage consumer to avoid duplicate Prometheus registrations).
    """
    rmq = settings.rabbitmq
    processor = AnalysisProcessor(
        ollama_base_url=settings.ollama.llm_base_url,
        shuffle_webhook_url=settings.shuffle_webhook_url,
        metrics=metrics,
        llm_timeout=settings.ollama.llm_timeout,
        llm_model=settings.ollama.llm_model,
        use_schema=settings.ollama.use_schema,
        response_policy_file=settings.response_policy_file,
    )
    return MessageConsumer(
        amqp_url=rmq.amqp_url,
        queue_name=rmq.reports_queue,
        processor=processor,
        on_error="requeue",
    )
