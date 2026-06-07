"""
RabbitMQ consumer for AEGIS pipeline.

Listens to the configured RabbitMQ queue for incoming Wazuh alerts.
For each message:
1. Parse JSON → WazuhLog
2. Call pipeline.process_log()
3. ACK if success | NACK + requeue if error

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
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)
from pydantic import ValidationError

from aegis.llm.client import OllamaClient
from aegis.middleware.models import WazuhLog
from aegis.middleware.pipeline import process_log
from aegis.monitoring.metrics import MetricsCollector
from aegis.rag.client import ChromaDBClient
from aegis.soar.client import ShuffleClient

logger = logging.getLogger(__name__)


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
        ollama_base_url: str = "http://10.0.0.1:11434",
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        shuffle_webhook_url: str = "http://shuffle:3001/api/v1/hooks/",
        metrics: MetricsCollector | None = None,
        suspicion_threshold: float = 0.5,
        slm_timeout: float = 10.0,
        llm_timeout: float = 45.0,
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
            ollama_base_url: Ollama API base URL.
            chromadb_host: ChromaDB server hostname.
            chromadb_port: ChromaDB server port.
            shuffle_webhook_url: Shuffle SOAR webhook URL.
            metrics: Optional metrics collector for Prometheus reporting.
            suspicion_threshold: Minimum SLM confidence to proceed (default: 0.5).
            slm_timeout: SLM inference timeout in seconds (default: 10).
            llm_timeout: LLM inference timeout in seconds (default: 45).
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user
        self.rabbitmq_password = rabbitmq_password
        self.rabbitmq_vhost = rabbitmq_vhost
        self.queue_name = queue_name

        self.ollama_base_url = ollama_base_url
        self.chromadb_host = chromadb_host
        self.chromadb_port = chromadb_port
        self.shuffle_webhook_url = shuffle_webhook_url
        self.metrics = metrics

        self.suspicion_threshold = suspicion_threshold
        self.slm_timeout = slm_timeout
        self.llm_timeout = llm_timeout

        self.connection: AbstractRobustConnection | None = None
        self.channel: AbstractChannel | None = None
        self.queue: AbstractQueue | None = None

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

            self.connection = connection
            self.channel = channel
            self.queue = queue

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
        shuffle_client = ShuffleClient(self.shuffle_webhook_url)

        try:
            async with ollama_client, chromadb_client, shuffle_client:
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
                                    shuffle_client,
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
        shuffle_client: ShuffleClient,
    ) -> None:
        """
        Handle a single message from RabbitMQ queue.

        Args:
            message: Incoming RabbitMQ message.
            ollama_client: Initialized Ollama client.
            chromadb_client: Initialized ChromaDB client.
            shuffle_client: Initialized Shuffle client.
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

            # Sequential processing: one message at a time. Ollama already
            # serializes inference on the Raspberry Pi, and prefetch_count=1
            # (set in connect()) keeps the broker from overloading the channel
            # during alert bursts — the backlog stays buffered server-side.
            # Monitor with Prometheus: aegis_pipeline_duration_seconds p95 > 30s

            # Process through pipeline
            report = await process_log(
                log=log,
                ollama_client=ollama_client,
                chromadb_client=chromadb_client,
                shuffle_client=shuffle_client,
                metrics=self.metrics,
                suspicion_threshold=self.suspicion_threshold,
                slm_timeout=self.slm_timeout,
                llm_timeout=self.llm_timeout,
            )

            # ACK message
            await message.ack()

            if report is not None:
                logger.info(
                    json.dumps(
                        {
                            "event": "report_generated",
                            "alert_id": str(log.id),
                            "danger_score": report.risk_score.danger_score,
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
