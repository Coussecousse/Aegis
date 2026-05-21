"""Unit tests for OllamaClient retry and fallback behavior."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from aegis.llm.client import OllamaClient
from aegis.middleware.models import LlmResponse, SlmResponse


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://localhost/api/generate")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)

    def json(self) -> dict[str, Any]:
        return self._payload


@pytest.mark.asyncio
async def test_generate_slm_valid_json() -> None:
    client = OllamaClient("http://localhost:11434")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(
            200,
            {
                "response": json.dumps(
                    {
                        "is_suspect": True,
                        "confidence": 0.8,
                        "behavior_category": "lateral_movement",
                        "reasoning_short": "Suspicious remote command execution",
                        "raw_probabilities": {"suspect": 0.8, "benign": 0.2},
                    }
                )
            },
        )

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    payload = await client.generate("tinyllama-aegis", "prompt", timeout=10.0)
    parsed = SlmResponse(**payload)

    assert parsed.confidence == 0.8
    assert parsed.behavior_category == "lateral_movement"


@pytest.mark.asyncio
async def test_generate_llm_valid_json() -> None:
    client = OllamaClient("http://localhost:11434")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(
            200,
            {
                "response": json.dumps(
                    {
                        "attack_confirmed": True,
                        "confidence": 0.91,
                        "attack_type": "Lateral movement",
                        "severity": "critical",
                        "affected_asset": "DC-01",
                        "asset_criticality": "tier0",
                        "plain_language_summary": "Threat confirmed",
                        "recommended_action": "Isolate source host",
                        "requires_human_validation": True,
                        "raw_probabilities": {"attack": 0.91, "false_positive": 0.09},
                    }
                )
            },
        )

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    payload = await client.generate("mistral-aegis", "prompt", timeout=45.0)
    parsed = LlmResponse(**payload)

    assert parsed.attack_confirmed is True
    assert parsed.confidence == 0.91


@pytest.mark.asyncio
async def test_generate_timeout_retries_three_times(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OllamaClient("http://localhost:11434")
    attempts = 0
    sleeps: list[float] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        nonlocal attempts
        _ = args
        _ = kwargs
        attempts += 1
        raise httpx.TimeoutException("timeout")

    async def _sleep(duration: float) -> None:
        sleeps.append(duration)

    monkeypatch.setattr(asyncio, "sleep", _sleep)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    with pytest.raises(TimeoutError):
        await client.generate("tinyllama-aegis", "prompt", timeout=10.0)

    assert attempts == 3
    assert sleeps == [1.0, 2.0]


@pytest.mark.asyncio
async def test_generate_malformed_json_falls_back_safely() -> None:
    client = OllamaClient("http://localhost:11434")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(200, {"response": "not-json-content"})

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    payload = await client.generate("mistral-aegis", "prompt", timeout=45.0)

    assert payload["confidence"] == 0.0
    assert payload["requires_human_validation"] is True


@pytest.mark.asyncio
async def test_generate_missing_confidence_defaults_to_zero() -> None:
    client = OllamaClient("http://localhost:11434")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(
            200,
            {
                "response": json.dumps(
                    {
                        "is_suspect": True,
                        "behavior_category": "normal",
                        "reasoning_short": "No strong signal",
                        "raw_probabilities": {"suspect": 0.4, "benign": 0.6},
                    }
                )
            },
        )

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    payload = await client.generate("tinyllama-aegis", "prompt", timeout=10.0)

    assert payload["confidence"] == 0.0


@pytest.mark.asyncio
async def test_generate_uses_distinct_models() -> None:
    client = OllamaClient("http://localhost:11434")
    models_seen: list[str] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        models_seen.append(str(kwargs["json"]["model"]))
        model = str(kwargs["json"]["model"])
        if model == "tinyllama-aegis":
            payload = {
                "response": json.dumps(
                    {
                        "is_suspect": False,
                        "confidence": 0.2,
                        "behavior_category": "normal",
                        "reasoning_short": "Benign",
                        "raw_probabilities": {"suspect": 0.2, "benign": 0.8},
                    }
                )
            }
        else:
            payload = {
                "response": json.dumps(
                    {
                        "attack_confirmed": False,
                        "confidence": 0.3,
                        "attack_type": "None",
                        "severity": "low",
                        "affected_asset": "WS-01",
                        "asset_criticality": "tier2",
                        "plain_language_summary": "Likely benign",
                        "recommended_action": "Monitor",
                        "requires_human_validation": True,
                        "raw_probabilities": {"attack": 0.3, "false_positive": 0.7},
                    }
                )
            }
        return _FakeResponse(200, payload)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    await client.generate("tinyllama-aegis", "slm prompt", timeout=10.0)
    await client.generate("mistral-aegis", "llm prompt", timeout=45.0)

    assert models_seen == ["tinyllama-aegis", "mistral-aegis"]
