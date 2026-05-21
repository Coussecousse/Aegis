"""Unit tests for RabbitMQConsumer message handling and resilience."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from aegis.middleware.consumer import RabbitMQConsumer
from aegis.middleware.models import WazuhLog


class _FakeMessage:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False
        self.nacked = False
        self.requeue: bool | None = None

    async def ack(self) -> None:
        self.acked = True

    async def nack(self, requeue: bool = False) -> None:
        self.nacked = True
        self.requeue = requeue


def _valid_log_payload() -> dict[str, Any]:
    log = WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="WS-01",
        source_ip="10.0.0.10",
        rule_id=1001,
        rule_level=8,
        rule_description="Suspicious command",
        full_log="cmd.exe /c net user",
        mitre_technique="T1021",
        decoder_name="windows-eventlog",
    )
    return log.model_dump(mode="json")


@pytest.mark.asyncio
async def test_handle_message_valid_json_calls_process_log(monkeypatch: pytest.MonkeyPatch) -> None:
    consumer = RabbitMQConsumer()
    called = {"value": False}

    async def _fake_process_log(**kwargs: Any) -> None:
        _ = kwargs
        called["value"] = True

    monkeypatch.setattr("aegis.middleware.consumer.process_log", _fake_process_log)

    message = _FakeMessage(json.dumps(_valid_log_payload()).encode("utf-8"))

    await consumer._handle_message(
        message,
        ollama_client=object(),
        chromadb_client=object(),
        shuffle_client=object(),
    )

    assert called["value"] is True
    assert message.acked is True


@pytest.mark.asyncio
async def test_handle_message_invalid_json_ack_no_requeue() -> None:
    consumer = RabbitMQConsumer()
    message = _FakeMessage(b"not-json")

    await consumer._handle_message(
        message,
        ollama_client=object(),
        chromadb_client=object(),
        shuffle_client=object(),
    )

    assert message.acked is True
    assert message.nacked is False


@pytest.mark.asyncio
async def test_handle_message_pipeline_exception_nack_no_requeue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumer = RabbitMQConsumer()

    async def _fake_process_log(**kwargs: Any) -> None:
        _ = kwargs
        raise RuntimeError("processing failed")

    monkeypatch.setattr("aegis.middleware.consumer.process_log", _fake_process_log)

    message = _FakeMessage(json.dumps(_valid_log_payload()).encode("utf-8"))

    await consumer._handle_message(
        message,
        ollama_client=object(),
        chromadb_client=object(),
        shuffle_client=object(),
    )

    assert message.nacked is True
    assert message.requeue is False


class _DummyClient:
    async def __aenter__(self) -> _DummyClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        _ = exc_type
        _ = exc_val
        _ = exc_tb
        return None


@pytest.mark.asyncio
async def test_start_reconnects_after_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumer = RabbitMQConsumer()
    attempts = 0

    async def _fake_connect() -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("rabbitmq down")
        raise asyncio.CancelledError

    async def _fake_close() -> None:
        return None

    async def _fake_sleep(duration: float) -> None:
        _ = duration

    monkeypatch.setattr(consumer, "connect", _fake_connect)
    monkeypatch.setattr(consumer, "close", _fake_close)
    monkeypatch.setattr("aegis.middleware.consumer.asyncio.sleep", _fake_sleep)
    monkeypatch.setattr(
        "aegis.middleware.consumer.OllamaClient",
        lambda *args, **kwargs: _DummyClient(),
    )
    monkeypatch.setattr(
        "aegis.middleware.consumer.ChromaDBClient",
        lambda *args, **kwargs: _DummyClient(),
    )
    monkeypatch.setattr(
        "aegis.middleware.consumer.ShuffleClient",
        lambda *args, **kwargs: _DummyClient(),
    )

    with pytest.raises(asyncio.CancelledError):
        await consumer.start()

    assert attempts >= 2
