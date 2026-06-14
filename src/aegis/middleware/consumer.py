"""Triage-stage processor for the AEGIS pipeline (fast SLM + RAG + gates).

Behind :class:`MessageConsumer` (queue ``aegis.triage``): decode a Wazuh alert,
run :func:`triage_log`, and publish escalated alerts onward to the analysis
stage. Talks to the dedicated SLM Ollama instance so a multi-minute LLM analysis
on the other instance never blocks triage.
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
from aegis.middleware.models import WazuhLog
from aegis.middleware.pipeline import triage_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.rag.client import ChromaDBClient

logger = logging.getLogger(__name__)

# Routing key used to hand escalated alerts from the triage stage to the
# analysis stage — bound to the (already provisioned) aegis.reports queue.
ESCALATED_ALERT_ROUTING_KEY = "alert.escalated"


class TriageProcessor:
    """Run SLM triage on one Wazuh alert and publish escalations onward."""

    def __init__(
        self,
        *,
        ollama_base_url: str = "http://10.0.0.1:11434",
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        metrics: MetricsCollector | None = None,
        suspicion_threshold: float = 0.5,
        slm_timeout: float = 10.0,
        slm_model: str = "qwen25-aegis",
    ) -> None:
        self.ollama_base_url = ollama_base_url
        self.chromadb_host = chromadb_host
        self.chromadb_port = chromadb_port
        self.metrics = metrics
        self.suspicion_threshold = suspicion_threshold
        self.slm_timeout = slm_timeout
        self.slm_model = slm_model

        self._stack: AsyncExitStack | None = None
        self._ollama: OllamaClient | None = None
        self._chroma: ChromaDBClient | None = None

    async def __aenter__(self) -> TriageProcessor:
        stack = AsyncExitStack()
        self._ollama = await stack.enter_async_context(OllamaClient(self.ollama_base_url))
        self._chroma = await stack.enter_async_context(
            ChromaDBClient(self.chromadb_host, self.chromadb_port)
        )
        self._stack = stack
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        """Triage one alert; publish an EscalatedAlert when it survives the gates."""
        if self._ollama is None or self._chroma is None:
            raise RuntimeError("TriageProcessor used outside its context manager")

        try:
            log = WazuhLog(**payload)
        except ValidationError as exc:
            raise UnprocessableMessageError(f"invalid WazuhLog: {exc}") from exc

        escalated = await triage_log(
            log=log,
            ollama_client=self._ollama,
            chromadb_client=self._chroma,
            metrics=self.metrics,
            suspicion_threshold=self.suspicion_threshold,
            slm_timeout=self.slm_timeout,
            slm_model=self.slm_model,
        )

        if escalated is not None:
            body = json.dumps(escalated.model_dump(mode="json")).encode("utf-8")
            await publish(ESCALATED_ALERT_ROUTING_KEY, body)
            logger.info(
                json.dumps(
                    {
                        "event": "alert_escalated",
                        "alert_id": str(log.id),
                        "report_id": str(escalated.report_id),
                    }
                )
            )
        else:
            logger.debug(json.dumps({"event": "alert_discarded", "alert_id": str(log.id)}))


def build_triage_consumer(
    settings: Settings, metrics: MetricsCollector | None = None
) -> MessageConsumer:
    """Build the triage MessageConsumer from settings."""
    rmq = settings.rabbitmq
    processor = TriageProcessor(
        ollama_base_url=settings.ollama.slm_base_url,
        chromadb_host=settings.chroma.host,
        chromadb_port=settings.chroma.port,
        metrics=metrics,
        suspicion_threshold=settings.suspicion_threshold,
        slm_timeout=settings.ollama.slm_timeout,
        slm_model=settings.ollama.slm_model,
    )
    return MessageConsumer(
        amqp_url=rmq.amqp_url,
        queue_name=rmq.triage_queue,
        processor=processor,
        on_error="requeue",
        exchange_name=rmq.exchange,
    )
