"""
RabbitMQ consumer for AEGIS pipeline — slow analysis stage.

Listens to the aegis.reports queue for EscalatedAlert bundles published by the
triage consumer. For each message:
1. Parse JSON → EscalatedAlert
2. Call pipeline.analyze_log() (LLM + risk scoring + report + SOAR)
3. ACK if success | NACK + requeue if error

Runs independently of the triage consumer so a multi-minute LLM analysis never
blocks the fast SLM triage loop. Connection resilience: reconnect on disconnect.
Zero cloud calls. On-premise RabbitMQ only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from urllib.parse import quote

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)
from pydantic import ValidationError

from aegis.llm.client import OllamaClient
from aegis.middleware.models import EscalatedAlert
from aegis.middleware.pipeline import analyze_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.soar.client import ShuffleClient
from aegis.vault.loader import load_secrets_to_env

logger = logging.getLogger(__name__)


class RabbitMQAnalysisConsumer:
    """Async RabbitMQ consumer dedicated to the slow LLM analysis stage."""

    def __init__(
        self,
        rabbitmq_host: str = "localhost",
        rabbitmq_port: int = 5672,
        rabbitmq_user: str = "guest",
        rabbitmq_password: str | None = None,
        rabbitmq_vhost: str = "aegis",
        queue_name: str = "aegis.reports",
        ollama_base_url: str = "http://10.0.0.1:11434",
        shuffle_webhook_url: str = "http://shuffle:3001/api/v1/hooks/",
        metrics: MetricsCollector | None = None,
        llm_timeout: float = 45.0,
        semaphore: asyncio.Semaphore | None = None,
    ) -> None:
        """
        Initialize the analysis consumer with connection parameters.

        Args:
            rabbitmq_host: RabbitMQ server hostname.
            rabbitmq_port: RabbitMQ server port.
            rabbitmq_user: RabbitMQ username.
            rabbitmq_password: RabbitMQ password.
            rabbitmq_vhost: RabbitMQ virtual host.
            queue_name: Queue to listen to (default: aegis.reports).
            ollama_base_url: Ollama API base URL.
            shuffle_webhook_url: Shuffle SOAR webhook URL.
            metrics: Optional metrics collector for Prometheus reporting — should
                be the SAME instance used by the triage consumer (Prometheus
                rejects duplicate metric registrations on a shared registry).
            llm_timeout: LLM inference timeout in seconds (default: 45).
            semaphore: Optional shared semaphore serializing Ollama inference calls
                across the triage and analysis consumers (see OllamaClient).
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user
        self.rabbitmq_password = rabbitmq_password
        self.rabbitmq_vhost = rabbitmq_vhost
        self.queue_name = queue_name

        self.ollama_base_url = ollama_base_url
        self.shuffle_webhook_url = shuffle_webhook_url
        self.metrics = metrics

        self.llm_timeout = llm_timeout
        self.semaphore = semaphore

        self.connection: AbstractRobustConnection | None = None
        self.channel: AbstractChannel | None = None
        self.queue: AbstractQueue | None = None

    async def connect(self) -> None:
        """Establish connection to RabbitMQ and bind to the reports queue."""
        encoded_user = quote(self.rabbitmq_user or "", safe="")
        safe_password = self.rabbitmq_password or ""
        encoded_password = quote(safe_password, safe="")
        encoded_vhost = quote(self.rabbitmq_vhost or "/", safe="")
        connection_url = (
            f"amqp://{encoded_user}:{encoded_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/{encoded_vhost}"
        )

        connection = await aio_pika.connect_robust(connection_url)
        channel = await connection.channel()

        # Same rationale as the triage consumer: hold back delivery to one
        # unacked message at a time so a backlog of escalated alerts stays
        # buffered server-side instead of overloading the channel.
        await channel.set_qos(prefetch_count=1)

        queue = await channel.declare_queue(self.queue_name, passive=True)

        self.connection = connection
        self.channel = channel
        self.queue = queue

        logger.info(f"Connected to RabbitMQ. Listening to queue: {self.queue_name}")

    async def start(self) -> None:
        """
        Start consuming escalated alerts from RabbitMQ indefinitely.

        Runs the slow LLM analysis stage independently of the triage consumer.
        """
        ollama_client = OllamaClient(self.ollama_base_url, semaphore=self.semaphore)
        shuffle_client = ShuffleClient(self.shuffle_webhook_url)

        try:
            async with ollama_client, shuffle_client:
                while True:
                    try:
                        await self.connect()

                        logger.info("Starting analysis consumer loop...")
                        if self.queue is None:
                            raise RuntimeError("Queue not initialized")

                        async with self.queue.iterator() as queue_iter:
                            async for message in queue_iter:
                                await self._handle_message(message, ollama_client, shuffle_client)

                    except asyncio.CancelledError:
                        logger.info("Analysis consumer cancelled. Shutting down...")
                        raise
                    except Exception as e:
                        logger.warning(f"Analysis consumer loop interrupted, reconnecting: {e}")
                        await self.close()
                        await asyncio.sleep(2.0)

        finally:
            await self.close()

    async def _handle_message(
        self,
        message: AbstractIncomingMessage,
        ollama_client: OllamaClient,
        shuffle_client: ShuffleClient,
    ) -> None:
        """
        Handle a single escalated-alert message from RabbitMQ.

        Args:
            message: Incoming RabbitMQ message carrying an EscalatedAlert.
            ollama_client: Initialized Ollama client.
            shuffle_client: Initialized Shuffle client.
        """
        try:
            payload = json.loads(message.body.decode("utf-8"))

            try:
                escalated = EscalatedAlert(**payload)
            except ValidationError as e:
                logger.warning(
                    json.dumps(
                        {
                            "event": "invalid_escalated_alert_format",
                            "error": str(e),
                        }
                    )
                )
                # ACK invalid messages (don't requeue)
                await message.ack()
                return

            logger.debug(
                json.dumps(
                    {
                        "event": "escalated_alert_received",
                        "alert_id": str(escalated.log.id),
                        "report_id": str(escalated.report_id),
                    }
                )
            )

            report = await analyze_log(
                escalated=escalated,
                ollama_client=ollama_client,
                shuffle_client=shuffle_client,
                metrics=self.metrics,
                llm_timeout=self.llm_timeout,
            )

            await message.ack()

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

        except json.JSONDecodeError:
            logger.error(
                json.dumps(
                    {
                        "event": "invalid_json_body",
                        "body_preview": message.body.decode("utf-8", errors="replace")[:200],
                    }
                )
            )
            # ACK poison pills: malformed JSON cannot be recovered by requeueing.
            await message.ack()

        except Exception as e:
            logger.error(
                json.dumps(
                    {
                        "event": "message_processing_error",
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )
            )
            # NACK and requeue so a transient failure can be retried.
            await message.nack(requeue=True)

    async def close(self) -> None:
        """Close RabbitMQ connection for the analysis consumer."""
        if self.connection is not None:
            await self.connection.close()
            logger.info("RabbitMQ analysis consumer connection closed")


def build_analysis_consumer_from_env(
    metrics: MetricsCollector | None = None,
    semaphore: asyncio.Semaphore | None = None,
) -> RabbitMQAnalysisConsumer:
    """Build an analysis consumer instance from environment variables.

    Args:
        metrics: Shared MetricsCollector instance (must be the same one passed
            to the triage consumer to avoid duplicate Prometheus registrations).
        semaphore: Shared semaphore serializing Ollama inference calls.

    Returns:
        RabbitMQAnalysisConsumer configured from environment.
    """
    load_secrets_to_env()

    return RabbitMQAnalysisConsumer(
        rabbitmq_host=os.getenv("RABBITMQ_HOST", "localhost"),
        rabbitmq_port=int(os.getenv("RABBITMQ_PORT", "5672")),
        rabbitmq_user=os.getenv("RABBITMQ_USER", "guest"),
        rabbitmq_password=os.getenv("RABBITMQ_PASSWORD", "guest"),
        rabbitmq_vhost=os.getenv("RABBITMQ_VHOST", "aegis"),
        queue_name=os.getenv("RABBITMQ_REPORTS_QUEUE", "aegis.reports"),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://10.0.0.1:11434"),
        shuffle_webhook_url=os.getenv("SHUFFLE_WEBHOOK_URL", "http://shuffle:3001/api/v1/hooks/"),
        metrics=metrics,
        llm_timeout=float(os.getenv("LLM_TIMEOUT", "45.0")),
        semaphore=semaphore,
    )
