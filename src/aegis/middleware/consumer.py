"""
RabbitMQ consumer for AEGIS pipeline — fast triage stage.

Listens to the configured RabbitMQ queue for incoming Wazuh alerts.
For each message:
1. Parse JSON → WazuhLog
2. Call pipeline.triage_log() (SLM + RAG + gates)
3. Publish escalated alerts to aegis.reports for the analysis consumer
4. ACK if success | NACK + requeue if error

Handles connection resilience: reconnect on disconnect.
Zero cloud calls. On-premise RabbitMQ only.
"""

import asyncio
import json
import logging
from urllib.parse import quote

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractExchange,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)
from pydantic import ValidationError

from aegis.llm.client import OllamaClient
from aegis.middleware.models import WazuhLog
from aegis.middleware.pipeline import triage_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.rag.client import ChromaDBClient

logger = logging.getLogger(__name__)

# Routing key used to hand escalated alerts from the triage stage to the
# analysis stage — bound to the (already provisioned) aegis.reports queue.
ESCALATED_ALERT_ROUTING_KEY = "alert.escalated"


class RabbitMQConsumer:
    """Async RabbitMQ consumer for Wazuh alerts."""

    def __init__(
        self,
        rabbitmq_host: str = "localhost",
        rabbitmq_port: int = 5672,
        rabbitmq_user: str = "guest",
        rabbitmq_password: str | None = None,
        rabbitmq_vhost: str = "aegis",
        queue_name: str = "aegis.triage",
        exchange_name: str = "aegis.alerts",
        ollama_base_url: str = "http://10.0.0.1:11434",
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        metrics: MetricsCollector | None = None,
        suspicion_threshold: float = 0.5,
        slm_timeout: float = 10.0,
    ) -> None:
        """
        Initialize RabbitMQ consumer with connection parameters.

        Args:
            rabbitmq_host: RabbitMQ server hostname.
            rabbitmq_port: RabbitMQ server port.
            rabbitmq_user: RabbitMQ username.
            rabbitmq_password: RabbitMQ password.
            rabbitmq_vhost: RabbitMQ virtual host.
            queue_name: Queue to listen to (default: aegis.triage).
            exchange_name: Exchange to publish escalated alerts to (default: aegis.alerts).
            ollama_base_url: Base URL of the SLM Ollama instance.
            chromadb_host: ChromaDB server hostname.
            chromadb_port: ChromaDB server port.
            metrics: Optional metrics collector for Prometheus reporting.
            suspicion_threshold: Minimum SLM confidence to proceed (default: 0.5).
            slm_timeout: SLM inference timeout in seconds (default: 10).
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user
        self.rabbitmq_password = rabbitmq_password
        self.rabbitmq_vhost = rabbitmq_vhost
        self.queue_name = queue_name
        self.exchange_name = exchange_name

        self.ollama_base_url = ollama_base_url
        self.chromadb_host = chromadb_host
        self.chromadb_port = chromadb_port
        self.metrics = metrics

        self.suspicion_threshold = suspicion_threshold
        self.slm_timeout = slm_timeout

        self.connection: AbstractRobustConnection | None = None
        self.channel: AbstractChannel | None = None
        self.queue: AbstractQueue | None = None
        self.exchange: AbstractExchange | None = None

    async def connect(self) -> None:
        """
        Establish connection to RabbitMQ.

        Raises:
            aio_pika.AMQPException: If connection fails.
        """
        logger.info(f"Connecting to RabbitMQ: {self.rabbitmq_host}:" f"{self.rabbitmq_port}")

        # Build connection URL
        encoded_user = quote(self.rabbitmq_user or "", safe="")
        safe_password = self.rabbitmq_password or ""
        encoded_password = quote(safe_password, safe="")
        encoded_vhost = quote(self.rabbitmq_vhost or "/", safe="")
        connection_url = (
            f"amqp://{encoded_user}:{encoded_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/{encoded_vhost}"
        )

        try:
            connection = await aio_pika.connect_robust(connection_url)
            channel = await connection.channel()

            # Hold back the broker's delivery to one unacked message at a time.
            # Without this, RabbitMQ pushes the entire backlog onto the channel —
            # during a Kali scan burst this overloaded the channel (~900 messages)
            # and crashed it (ChannelInvalidStateError) while the slow Pi pipeline
            # (~6 min/alert, dominated by LLM inference) was still on message #1.
            await channel.set_qos(prefetch_count=1)

            # Attach to the queue provisioned by RabbitMQ definitions.
            queue = await channel.declare_queue(
                self.queue_name,
                passive=True,
            )

            # Resolve the alerts exchange so escalated alerts can be published
            # onward to the analysis stage (queue aegis.reports).
            exchange = await channel.get_exchange(self.exchange_name, ensure=True)

            self.connection = connection
            self.channel = channel
            self.queue = queue
            self.exchange = exchange

            logger.info(f"Connected to RabbitMQ. Listening to queue: {self.queue_name}")

        except Exception as e:
            logger.error(f"RabbitMQ connection failed: {e}")
            raise

    async def start(self) -> None:
        """
        Start consuming messages from RabbitMQ queue.

        Runs indefinitely until interrupted (SIGTERM/SIGINT).
        Processes each message through the AEGIS pipeline.
        """
        ollama_client = OllamaClient(self.ollama_base_url)
        chromadb_client = ChromaDBClient(self.chromadb_host, self.chromadb_port)

        try:
            async with ollama_client, chromadb_client:
                while True:
                    try:
                        await self.connect()

                        logger.info("Starting message consumer loop...")
                        if self.queue is None:
                            raise RuntimeError("Queue not initialized")

                        async with self.queue.iterator() as queue_iter:
                            async for message in queue_iter:
                                await self._handle_message(
                                    message,
                                    ollama_client,
                                    chromadb_client,
                                )

                    except asyncio.CancelledError:
                        logger.info("Consumer cancelled. Shutting down...")
                        raise
                    except Exception as e:
                        logger.warning(f"Consumer loop interrupted, reconnecting: {e}")
                        await self.close()
                        await asyncio.sleep(2.0)

        finally:
            await self.close()

    async def _handle_message(
        self,
        message: AbstractIncomingMessage,
        ollama_client: OllamaClient,
        chromadb_client: ChromaDBClient,
    ) -> None:
        """
        Handle a single message from RabbitMQ queue.

        Args:
            message: Incoming RabbitMQ message.
            ollama_client: Initialized Ollama client.
            chromadb_client: Initialized ChromaDB client.
        """
        try:
            # Parse message body
            log_data = json.loads(message.body.decode("utf-8"))

            # Validate and construct WazuhLog
            try:
                log = WazuhLog(**log_data)
            except ValidationError as e:
                logger.warning(
                    json.dumps(
                        {
                            "event": "invalid_log_format",
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
                        "event": "message_received",
                        "alert_id": str(log.id),
                        "rule_id": log.rule_id,
                    }
                )
            )

            # Sequential processing: one message at a time. prefetch_count=1
            # (set in connect()) keeps the broker from overloading the channel
            # during alert bursts — the backlog stays buffered server-side.
            # This consumer's OllamaClient talks to the dedicated SLM Ollama
            # instance, so a long-running LLM analysis on the other instance
            # never blocks triage.

            # Triage: SLM + RAG + gates
            escalated = await triage_log(
                log=log,
                ollama_client=ollama_client,
                chromadb_client=chromadb_client,
                metrics=self.metrics,
                suspicion_threshold=self.suspicion_threshold,
                slm_timeout=self.slm_timeout,
            )

            if escalated is not None:
                if self.exchange is None:
                    raise RuntimeError("Exchange not initialized")

                body = json.dumps(escalated.model_dump(mode="json")).encode("utf-8")
                escalated_message = aio_pika.Message(body=body, content_type="application/json")
                await self.exchange.publish(
                    escalated_message, routing_key=ESCALATED_ALERT_ROUTING_KEY
                )

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
                logger.debug(
                    json.dumps(
                        {
                            "event": "alert_discarded",
                            "alert_id": str(log.id),
                        }
                    )
                )

            # ACK message
            await message.ack()

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
        """Close RabbitMQ connection."""
        if self.connection is not None:
            await self.connection.close()
            logger.info("RabbitMQ connection closed")
