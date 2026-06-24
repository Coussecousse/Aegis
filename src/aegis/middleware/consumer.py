"""Triage-stage processor for the AEGIS pipeline (fast SLM + RAG + gates).

Behind :class:`MessageConsumer` (queue ``aegis.triage``): decode a Wazuh alert,
run :func:`triage_log`, and publish escalated alerts onward to the analysis
stage. Talks to the dedicated SLM Ollama instance so a multi-minute LLM analysis
on the other instance never blocks triage.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import AsyncExitStack
from typing import Any

from pydantic import ValidationError

from aegis.config import Settings
from aegis.identity_store.postgres_client import PostgresIdentityStore
from aegis.llm.client import OllamaClient
from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
)
from aegis.middleware.models import WazuhLog
from aegis.middleware.pipeline import triage_log
from aegis.monitoring.metrics import MetricsCollector

logger = logging.getLogger(__name__)

# Routing key used to hand escalated alerts from the triage stage to the
# analysis stage — bound to the (already provisioned) aegis.reports queue.
ESCALATED_ALERT_ROUTING_KEY = "alert.escalated"

# Routing key that enqueues an identity-sync job — bound to the identity.sync queue.
IDENTITY_SYNC_ROUTING_KEY = "identity.sync"
# Don't re-enqueue a sync for the same asset within this window (the first sync is
# still in flight); once it lands, has_baseline flips True and triage stops asking.
_IDENTITY_SYNC_DEDUP_TTL = 300.0


class TriageProcessor:
    """Run SLM triage on one Wazuh alert and publish escalations onward."""

    def __init__(
        self,
        *,
        ollama_base_url: str = "http://10.0.0.1:11434",
        postgres_host: str = "localhost",
        postgres_port: int = 5432,
        postgres_db: str = "aegis",
        postgres_user: str = "aegis_app",
        postgres_password: str = "",
        metrics: MetricsCollector | None = None,
        suspicion_threshold: float = 0.5,
        slm_timeout: float = 10.0,
        slm_model: str = "qwen25-aegis",
        fp_gate_confidence_ceiling: float = 0.6,
    ) -> None:
        self.ollama_base_url = ollama_base_url
        self.postgres_host = postgres_host
        self.postgres_port = postgres_port
        self.postgres_db = postgres_db
        self.postgres_user = postgres_user
        self.postgres_password = postgres_password
        self.metrics = metrics
        self.suspicion_threshold = suspicion_threshold
        self.slm_timeout = slm_timeout
        self.slm_model = slm_model
        self.fp_gate_confidence_ceiling = fp_gate_confidence_ceiling

        self._stack: AsyncExitStack | None = None
        self._ollama: OllamaClient | None = None
        self._postgres: PostgresIdentityStore | None = None
        self._recently_synced: dict[str, float] = {}

    async def __aenter__(self) -> TriageProcessor:
        stack = AsyncExitStack()
        self._ollama = await stack.enter_async_context(OllamaClient(self.ollama_base_url))
        self._postgres = await stack.enter_async_context(
            PostgresIdentityStore(
                self.postgres_host,
                self.postgres_port,
                self.postgres_db,
                self.postgres_user,
                self.postgres_password,
            )
        )
        self._stack = stack
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    def _should_request_sync(self, asset_id: str, now: float) -> bool:
        """True (and records) when an identity sync for this asset is not deduped."""
        last = self._recently_synced.get(asset_id)
        if last is not None and now - last < _IDENTITY_SYNC_DEDUP_TTL:
            return False
        self._recently_synced[asset_id] = now
        return True

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        """Triage one alert; publish an EscalatedAlert when it survives the gates."""
        if self._ollama is None or self._postgres is None:
            raise RuntimeError("TriageProcessor used outside its context manager")

        try:
            log = WazuhLog(**payload)
        except ValidationError as exc:
            raise UnprocessableMessageError(f"invalid WazuhLog: {exc}") from exc

        async def _request_identity_sync(asset_id: str) -> None:
            if not self._should_request_sync(asset_id, time.monotonic()):
                return
            body = json.dumps({"asset_id": asset_id}).encode("utf-8")
            try:
                await publish(IDENTITY_SYNC_ROUTING_KEY, body)
                logger.info(json.dumps({"event": "identity_sync_requested", "asset_id": asset_id}))
            except Exception as exc:  # a sync-publish failure must not drop the alert
                logger.warning(
                    json.dumps(
                        {"event": "identity_sync_failed", "asset_id": asset_id, "error": str(exc)}
                    )
                )

        escalated = await triage_log(
            log=log,
            ollama_client=self._ollama,
            chromadb_client=self._postgres,
            metrics=self.metrics,
            suspicion_threshold=self.suspicion_threshold,
            slm_timeout=self.slm_timeout,
            slm_model=self.slm_model,
            on_unprofiled_asset=_request_identity_sync,
            fp_gate_confidence_ceiling=self.fp_gate_confidence_ceiling,
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
        postgres_host=settings.postgres.host,
        postgres_port=settings.postgres.port,
        postgres_db=settings.postgres.database,
        postgres_user=settings.postgres.user,
        postgres_password=settings.postgres.password,
        metrics=metrics,
        suspicion_threshold=settings.suspicion_threshold,
        slm_timeout=settings.ollama.slm_timeout,
        slm_model=settings.ollama.slm_model,
        fp_gate_confidence_ceiling=settings.fp_gate_confidence_ceiling,
    )
    return MessageConsumer(
        amqp_url=rmq.amqp_url,
        queue_name=rmq.triage_queue,
        processor=processor,
        on_error="requeue",
        exchange_name=rmq.exchange,
    )
