"""Unit tests for OllamaClient behavior."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from aegis.llm.client import OllamaClient


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
async def test_generate_valid_json_returns_dict() -> None:
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

    assert payload["is_suspect"] is True
    assert payload["confidence"] == 0.8


@pytest.mark.asyncio
async def test_generate_format_defaults_to_json_string() -> None:
    client = OllamaClient("http://localhost:11434")
    captured: dict[str, Any] = {}

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        captured.update(kwargs.get("json", {}))
        return _FakeResponse(200, {"response": json.dumps({"confidence": 0.5})})

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    await client.generate("mistral-aegis", "prompt", timeout=10.0)

    assert captured["format"] == "json"


@pytest.mark.asyncio
async def test_generate_passes_format_schema_when_provided() -> None:
    client = OllamaClient("http://localhost:11434")
    captured: dict[str, Any] = {}
    schema = {"type": "object", "required": ["attack_confirmed"]}

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        captured.update(kwargs.get("json", {}))
        return _FakeResponse(200, {"response": json.dumps({"confidence": 0.5})})

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    await client.generate("mistral-aegis", "prompt", timeout=10.0, format_schema=schema)

    assert captured["format"] == schema


@pytest.mark.asyncio
async def test_generate_timeout_retries_then_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OllamaClient("http://localhost:11434")
    attempts = 0
    sleeps: list[float] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        nonlocal attempts
        _ = args
        _ = kwargs
        attempts += 1
        raise httpx.TimeoutException("timeout")

    async def _sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", _sleep)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    with pytest.raises(httpx.TimeoutException):
        await client.generate("tinyllama-aegis", "prompt", timeout=10.0)

    assert attempts == 3
    assert sleeps == [1.0, 2.0]


@pytest.mark.asyncio
async def test_extract_json_when_response_starts_with_brace() -> None:
    client = OllamaClient("http://localhost:11434")

    wrapped = (
        '{"is_suspect":true,"confidence":0.7,"behavior_category":"normal",'
        '"reasoning_short":"ok","raw_probabilities":{"suspect":0.7,"benign":0.3}} '
        "trailing"
    )

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(200, {"response": wrapped})

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    payload = await client.generate("tinyllama-aegis", "prompt", timeout=10.0)

    assert payload["behavior_category"] == "normal"
    assert payload["confidence"] == 0.7


@pytest.mark.asyncio
async def test_generate_non_extractable_json_raises_value_error() -> None:
    client = OllamaClient("http://localhost:11434")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(200, {"response": "not-json-at-all"})

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="Response is not valid JSON"):
        await client.generate("tinyllama-aegis", "prompt", timeout=10.0)


@pytest.mark.asyncio
async def test_generate_sends_expected_model_names() -> None:
    client = OllamaClient("http://localhost:11434")
    sent_models: list[str] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        sent_models.append(str(kwargs["json"]["model"]))
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

    assert sent_models == ["tinyllama-aegis", "mistral-aegis"]


@pytest.mark.asyncio
async def test_generate_posts_to_its_own_instance_base_url() -> None:
    """Each OllamaClient only ever talks to its configured base_url — this is
    what lets the SLM and LLM run as two independent Ollama instances pinned
    to separate CPU cores, with no cross-talk and no shared lock between them.
    """
    slm_client = OllamaClient("http://10.0.0.1:11434")
    llm_client = OllamaClient("http://10.0.0.1:11435")
    requested_urls: list[str] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        requested_urls.append(str(args[0]))
        _ = kwargs
        return _FakeResponse(200, {"response": json.dumps({"confidence": 0.5})})

    for client in (slm_client, llm_client):
        client._client = httpx.AsyncClient()
        client._client.post = _post  # type: ignore[method-assign]

    await slm_client.generate("qwen25-aegis", "slm prompt", timeout=10.0)
    await llm_client.generate("mistral-aegis", "llm prompt", timeout=45.0)

    assert requested_urls == [
        "http://10.0.0.1:11434/api/generate",
        "http://10.0.0.1:11435/api/generate",
    ]
