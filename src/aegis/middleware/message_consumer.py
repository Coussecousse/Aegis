"""Generic RabbitMQ message-consuming module for AEGIS.

One deep module owns everything every consumer needs: connection, prefetch,
the reconnect loop, JSON decoding, and the ack / dead-letter / requeue policy.
Each pipeline stage supplies only a thin :class:`MessageProcessor` — what to do
with one decoded payload — instead of re-implementing the AMQP machinery.

Ack/nack contract (single place, was previously copy-pasted and divergent):
- undecodable JSON         -> ack (poison, can never succeed)
- ``UnprocessableMessageError`` -> ack (poison: failed validation/shape)
- any other exception      -> nack, requeued or dead-lettered per ``on_error``
- success                  -> ack
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractExchange,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)

logger = logging.getLogger(__name__)

# How a transient (non-poison) processing failure is handled.
ErrorPolicy = Literal["requeue", "dead_letter"]

# Publish one message body to a routing key on the consumer's exchange.
Publisher = Callable[[str, bytes], Awaitable[None]]


class UnprocessableMessageError(Exception):
    """A message that can never succeed (bad shape/validation) — ack and drop."""


class MessageProcessor(Protocol):
    """What a pipeline stage must provide to run behind :class:`MessageConsumer`.

    The processor is entered as an async context manager once per consumer run
    (open clients/connectors there), then ``process`` is called per message.
    """

    async def __aenter__(self) -> MessageProcessor: ...

    async def __aexit__(self, *exc_info: object) -> None: ...

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        """Handle one decoded payload.

        Raise :class:`UnprocessableMessageError` for a poison message (it will be
        ack'd and dropped); raise anything else for a transient failure (handled
        per the consumer's :class:`ErrorPolicy`). ``publish`` forwards a message
        to the consumer's exchange (only meaningful when the consumer was given
        an ``exchange_name``).
        """
        ...


class MessageConsumer:
    """Consume one RabbitMQ queue and drive a :class:`MessageProcessor`."""

    def __init__(
        self,
        *,
        amqp_url: str,
        queue_name: str,
        processor: MessageProcessor,
        on_error: ErrorPolicy = "requeue",
        exchange_name: str | None = None,
        prefetch_count: int = 1,
        reconnect_delay: float = 2.0,
    ) -> None:
        """Initialize the consumer.

        Args:
            amqp_url: Full amqp:// connection URL (e.g. ``RabbitMQSettings.amqp_url``).
            queue_name: Queue to consume (declared passively — must pre-exist).
            processor: Per-stage payload handler.
            on_error: Transient-failure policy: requeue for retry, or dead_letter.
            exchange_name: Exchange to resolve for ``publish``; None if the stage
                never publishes onward.
            prefetch_count: Unacked-message window (1 keeps bursts buffered
                server-side instead of overloading the channel).
            reconnect_delay: Seconds to wait before reconnecting after a drop.
        """
        self._amqp_url = amqp_url
        self._queue_name = queue_name
        self._processor = processor
        self._on_error = on_error
        self._exchange_name = exchange_name
        self._prefetch_count = prefetch_count
        self._reconnect_delay = reconnect_delay

        self._connection: AbstractRobustConnection | None = None
        self._channel: AbstractChannel | None = None
        self._queue: AbstractQueue | None = None
        self._exchange: AbstractExchange | None = None

    async def _connect(self) -> None:
        """Open the connection/channel, set prefetch, bind queue and exchange."""
        connection = await aio_pika.connect_robust(self._amqp_url)
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=self._prefetch_count)
        queue = await channel.declare_queue(self._queue_name, passive=True)
        exchange = (
            await channel.get_exchange(self._exchange_name, ensure=True)
            if self._exchange_name is not None
            else None
        )

        self._connection = connection
        self._channel = channel
        self._queue = queue
        self._exchange = exchange
        logger.info(f"Connected to RabbitMQ. Listening to queue: {self._queue_name}")

    async def _publish(self, routing_key: str, body: bytes) -> None:
        """Publish a message body to the resolved exchange."""
        if self._exchange is None:
            raise RuntimeError("MessageConsumer has no exchange to publish to")
        message = aio_pika.Message(body=body, content_type="application/json")
        await self._exchange.publish(message, routing_key=routing_key)

    async def start(self) -> None:
        """Consume indefinitely, reconnecting on drops, until cancelled."""
        async with self._processor:
            try:
                while True:
                    try:
                        await self._connect()
                        if self._queue is None:
                            raise RuntimeError("Queue not initialized")
                        async with self._queue.iterator() as queue_iter:
                            async for message in queue_iter:
                                await self._handle(message)
                    except asyncio.CancelledError:
                        logger.info(f"Consumer ({self._queue_name}) cancelled. Shutting down...")
                        raise
                    except Exception as exc:
                        logger.warning(
                            f"Consumer ({self._queue_name}) interrupted, reconnecting: {exc}"
                        )
                        await self._close()
                        await asyncio.sleep(self._reconnect_delay)
            finally:
                await self._close()

    async def _handle(self, message: AbstractIncomingMessage) -> None:
        """Decode one message and apply the ack/nack policy around the processor."""
        try:
            payload = json.loads(message.body.decode("utf-8"))
        except json.JSONDecodeError:
            logger.error(
                json.dumps(
                    {
                        "event": "invalid_json_body",
                        "queue": self._queue_name,
                        "body_preview": message.body.decode("utf-8", errors="replace")[:200],
                    }
                )
            )
            await message.ack()  # poison: requeueing can never fix bad JSON
            return

        if not isinstance(payload, dict):
            logger.error(json.dumps({"event": "non_object_payload", "queue": self._queue_name}))
            await message.ack()
            return

        try:
            await self._processor.process(payload, self._publish)
            await message.ack()
        except UnprocessableMessageError as exc:
            logger.warning(
                json.dumps(
                    {
                        "event": "unprocessable_message",
                        "queue": self._queue_name,
                        "error": str(exc),
                    }
                )
            )
            await message.ack()  # poison: failed validation/shape
        except Exception as exc:
            requeue = self._on_error == "requeue"
            logger.error(
                json.dumps(
                    {
                        "event": "message_processing_error",
                        "queue": self._queue_name,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                        "action": "requeue" if requeue else "dead_letter",
                    }
                )
            )
            await message.nack(requeue=requeue)

    async def _close(self) -> None:
        """Close the connection if open."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            self._channel = None
            self._queue = None
            self._exchange = None
            logger.info(f"RabbitMQ connection closed ({self._queue_name})")
