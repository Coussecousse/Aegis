"""Unit tests for the generic MessageConsumer publish reliability."""

from __future__ import annotations

import aio_pika
import pytest

from aegis.middleware.message_consumer import MessageConsumer


class _FakeProcessor:
    async def __aenter__(self) -> _FakeProcessor:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def process(self, payload: dict, publish: object) -> None:
        _ = (payload, publish)


def _consumer() -> MessageConsumer:
    return MessageConsumer(
        amqp_url="amqp://guest:guest@localhost/aegis",  # pragma: allowlist secret
        queue_name="aegis.triage",
        processor=_FakeProcessor(),
        exchange_name="aegis.alerts",
    )


@pytest.mark.asyncio
async def test_publish_is_persistent() -> None:
    captured: list[object] = []

    class _FakeExchange:
        async def publish(self, message: object, routing_key: str) -> None:
            _ = routing_key
            captured.append(message)

    consumer = _consumer()
    consumer._exchange = _FakeExchange()  # type: ignore[assignment]  # noqa: SLF001

    await consumer._publish("alert.escalated", b"{}")  # noqa: SLF001

    # An escalated alert must survive a broker restart — published persistent.
    assert captured[0].delivery_mode == aio_pika.DeliveryMode.PERSISTENT  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_publish_without_exchange_raises() -> None:
    consumer = _consumer()  # _exchange stays None until connected
    with pytest.raises(RuntimeError):
        await consumer._publish("alert.escalated", b"{}")  # noqa: SLF001
