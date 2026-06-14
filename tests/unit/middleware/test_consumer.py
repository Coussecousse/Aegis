"""Unit tests for the triage processor and the generic MessageConsumer policy."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from aegis.middleware.consumer import ESCALATED_ALERT_ROUTING_KEY, TriageProcessor
from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
)
from aegis.middleware.models import (
    EscalatedAlert,
    RagContext,
    SlmResponse,
    UEBAMetrics,
    WazuhLog,
)


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


def _escalated() -> EscalatedAlert:
    log = WazuhLog(**_valid_log_payload())
    return EscalatedAlert(
        report_id=uuid4(),
        pipeline_start=datetime.now(UTC),
        start_time=1.0,
        log=log,
        slm_analysis=SlmResponse(
            is_suspect=True,
            confidence=0.9,
            behavior_category="lateral_movement",
            reasoning_short="Suspicious behavior",
            raw_probabilities={"suspect": 0.9, "benign": 0.1},
        ),
        rag_context=RagContext(
            asset_name="asset-01",
            asset_criticality="tier1",
            asset_description="Production system",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="Normal business-hours activity",
                associated_users=["operator"],
                normal_activity_window="08:00-18:00",
                recent_anomalies=[],
                anomaly_score=0.1,
            ),
        ),
    )


# --------------------------------------------------------------------------- #
# TriageProcessor (the per-stage payload handler)
# --------------------------------------------------------------------------- #


def _entered_triage_processor() -> TriageProcessor:
    """A TriageProcessor with fake clients injected (bypassing __aenter__)."""
    proc = TriageProcessor()
    proc._ollama = object()  # type: ignore[assignment]  # noqa: SLF001
    proc._chroma = object()  # type: ignore[assignment]  # noqa: SLF001
    return proc


@pytest.mark.asyncio
async def test_triage_processor_escalation_publishes(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _entered_triage_processor()
    escalated = _escalated()

    async def _fake_triage_log(**kwargs: Any) -> EscalatedAlert:
        _ = kwargs
        return escalated

    monkeypatch.setattr("aegis.middleware.consumer.triage_log", _fake_triage_log)

    published: list[tuple[str, bytes]] = []

    async def _publish(routing_key: str, body: bytes) -> None:
        published.append((routing_key, body))

    await proc.process(_valid_log_payload(), _publish)

    assert len(published) == 1
    assert published[0][0] == ESCALATED_ALERT_ROUTING_KEY


@pytest.mark.asyncio
async def test_triage_processor_discard_does_not_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _entered_triage_processor()

    async def _fake_triage_log(**kwargs: Any) -> None:
        _ = kwargs
        return None

    monkeypatch.setattr("aegis.middleware.consumer.triage_log", _fake_triage_log)

    published: list[tuple[str, bytes]] = []

    async def _publish(routing_key: str, body: bytes) -> None:
        published.append((routing_key, body))

    await proc.process(_valid_log_payload(), _publish)

    assert published == []


@pytest.mark.asyncio
async def test_triage_processor_invalid_log_raises_unprocessable() -> None:
    proc = _entered_triage_processor()
    invalid_payload = {"id": str(uuid4()), "rule_id": 1001}  # missing required fields

    async def _publish(routing_key: str, body: bytes) -> None:  # pragma: no cover
        raise AssertionError("publish must not be called for an invalid log")

    with pytest.raises(UnprocessableMessageError):
        await proc.process(invalid_payload, _publish)


# --------------------------------------------------------------------------- #
# MessageConsumer (the generic ack/nack policy)
# --------------------------------------------------------------------------- #


class _FakeProcessor:
    def __init__(self, behaviour: str = "ok") -> None:
        self.behaviour = behaviour
        self.seen: list[dict[str, Any]] = []

    async def __aenter__(self) -> _FakeProcessor:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        _ = publish
        self.seen.append(payload)
        if self.behaviour == "poison":
            raise UnprocessableMessageError("bad shape")
        if self.behaviour == "transient":
            raise RuntimeError("boom")


def _consumer(processor: _FakeProcessor, on_error: str = "requeue") -> MessageConsumer:
    return MessageConsumer(
        amqp_url="amqp://guest:guest@localhost:5672/aegis",  # pragma: allowlist secret
        queue_name="q.test",
        processor=processor,
        on_error=on_error,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_handle_success_acks() -> None:
    proc = _FakeProcessor("ok")
    message = _FakeMessage(json.dumps({"k": "v"}).encode("utf-8"))

    await _consumer(proc)._handle(message)  # noqa: SLF001

    assert message.acked is True
    assert message.nacked is False
    assert proc.seen == [{"k": "v"}]


@pytest.mark.asyncio
async def test_handle_invalid_json_acks_without_calling_processor() -> None:
    proc = _FakeProcessor("ok")
    message = _FakeMessage(b"not-json")

    await _consumer(proc)._handle(message)  # noqa: SLF001

    assert message.acked is True
    assert message.nacked is False
    assert proc.seen == []


@pytest.mark.asyncio
async def test_handle_poison_message_acks() -> None:
    proc = _FakeProcessor("poison")
    message = _FakeMessage(json.dumps({"k": "v"}).encode("utf-8"))

    await _consumer(proc)._handle(message)  # noqa: SLF001

    assert message.acked is True
    assert message.nacked is False


@pytest.mark.asyncio
async def test_handle_transient_requeue_policy_nacks_with_requeue() -> None:
    proc = _FakeProcessor("transient")
    message = _FakeMessage(json.dumps({"k": "v"}).encode("utf-8"))

    await _consumer(proc, on_error="requeue")._handle(message)  # noqa: SLF001

    assert message.nacked is True
    assert message.requeue is True


@pytest.mark.asyncio
async def test_handle_transient_dead_letter_policy_nacks_without_requeue() -> None:
    proc = _FakeProcessor("transient")
    message = _FakeMessage(json.dumps({"k": "v"}).encode("utf-8"))

    await _consumer(proc, on_error="dead_letter")._handle(message)  # noqa: SLF001

    assert message.nacked is True
    assert message.requeue is False


@pytest.mark.asyncio
async def test_start_reconnects_after_connection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    consumer = _consumer(_FakeProcessor("ok"))
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

    monkeypatch.setattr(consumer, "_connect", _fake_connect)
    monkeypatch.setattr(consumer, "_close", _fake_close)
    monkeypatch.setattr("aegis.middleware.message_consumer.asyncio.sleep", _fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await consumer.start()

    assert attempts >= 2
