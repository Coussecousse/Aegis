"""
Ollama HTTP client for AEGIS LLM and SLM inference.

Provides an async interface to a single Ollama instance. AEGIS runs two
independent Ollama instances on the Raspberry Pi, each pinned to its own CPU
cores so a multi-minute LLM analysis never blocks SLM triage:
- SLM instance (Qwen 2.5 1.5B) on port 11434, 1 CPU core
- LLM instance (Mistral 7B Q4) on port 11435, the remaining CPU cores

Each consumer constructs its own OllamaClient pointed at its instance's
base_url (OLLAMA_SLM_BASE_URL / OLLAMA_LLM_BASE_URL).

Handles:
- HTTP requests to Ollama API (generate endpoint)
- Exponential retry (3 attempts: 1s/2s/4s backoff)
- Fallback JSON parsing with validation
- Zero external API calls (100% on-premise)

See docs/raspberrypi-ollama-setup.md for the two-instance setup.
"""

import asyncio
import json
import logging
from typing import Any, cast

import httpx

logger = logging.getLogger(__name__)


class OllamaClientError(RuntimeError):
    """Raised when Ollama request fails after all retries."""


class OllamaClient:
    """Async HTTP client for Ollama models (SLM + LLM inference)."""

    def __init__(self, base_url: str) -> None:
        """
        Initialize Ollama client.

        Args:
            base_url: Base URL of this Ollama instance (e.g.
                http://10.0.0.1:11434 for the SLM instance, or
                http://10.0.0.1:11435 for the LLM instance).
        """
        self.base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "OllamaClient":
        """Context manager entry."""
        self._client = httpx.AsyncClient(timeout=60.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        if self._client is not None:
            await self._client.aclose()

    async def generate(
        self,
        model: str,
        prompt: str,
        timeout: float = 45.0,
        keep_alive: int = 300,
        num_predict: int | None = None,
        format_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Generate response from Ollama model with exponential retry.

        Attempts up to 3 times with backoff: 1s, 2s, 4s.
        Parses JSON from response (constrained decoding via format=json).

        Args:
            model: Model name (e.g., "qwen25-aegis", "mistral-aegis").
            prompt: Prompt text to send to the model.
            timeout: Request timeout in seconds (SLM: 30s, LLM: 180s).
            keep_alive: Seconds to keep model in RAM after last request (default 5 min).
                        Pass -1 to keep indefinitely, 0 to unload immediately.
            num_predict: Max tokens to generate. On slow CPU-only inference (e.g.
                         Raspberry Pi), capping this keeps small-JSON responses (SLM
                         triage) within the timeout instead of running unbounded.
                         None lets Ollama use its own default.
            format_schema: Optional JSON Schema for Ollama structured outputs. When
                           provided, decoding is constrained to this exact shape (all
                           required keys, correct types) instead of free-form JSON —
                           requires Ollama >= 0.5. None falls back to ``format="json"``.

        Returns:
            dict: Parsed JSON response from model.

        Raises:
            ValueError: If response is not valid JSON after all retries.
            httpx.HTTPError: If all HTTP requests fail (after 3 retries).
        """
        return await self._generate_with_retry(
            model, prompt, timeout, keep_alive, num_predict, format_schema
        )

    async def _generate_with_retry(
        self,
        model: str,
        prompt: str,
        timeout: float,
        keep_alive: int,
        num_predict: int | None,
        format_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send the request to Ollama, retrying with exponential backoff on failure."""
        url = f"{self.base_url}/api/generate"
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # constrained decoding — a JSON Schema forces the exact shape (all keys,
            # right types); "json" only forces syntactically-valid free-form JSON.
            "format": format_schema if format_schema is not None else "json",
            "keep_alive": keep_alive,
        }
        if num_predict is not None:
            payload["options"] = {"num_predict": num_predict}

        backoff_times = [1.0, 2.0, 4.0]

        for attempt, backoff in enumerate(backoff_times, start=1):
            try:
                logger.debug(
                    f"[{model}] Attempt {attempt}/3 - sending to {url}",
                )

                if self._client is None:
                    self._client = httpx.AsyncClient(timeout=60.0)

                response = await self._client.post(
                    url,
                    json=payload,
                    timeout=timeout,
                )
                response.raise_for_status()

                response_data = response.json()
                response_text = ""
                if isinstance(response_data, dict):
                    response_text = str(response_data.get("response", ""))

                    parsed_json = self._extract_json(response_text)
                    parsed_json["confidence"] = self._normalize_confidence(
                        parsed_json.get("confidence")
                    )
                    logger.info(
                        f"[{model}] Success on attempt {attempt}: confidence "
                        f"{parsed_json.get('confidence', 'N/A')}"
                    )
                    return parsed_json

                raise ValueError(f"Unexpected Ollama response format: {type(response_data)}")

            except httpx.TimeoutException as exc:
                logger.warning(
                    f"[{model}] Attempt {attempt}/3 - TIMEOUT ({timeout}s). "
                    f"Retrying in {backoff}s..."
                )
                if attempt < len(backoff_times):
                    await asyncio.sleep(backoff)
                    continue
                raise exc

            except httpx.HTTPError as exc:
                logger.warning(
                    f"[{model}] Attempt {attempt}/3 - ERROR: {type(exc).__name__}: {exc}. "
                    f"Retrying in {backoff}s..."
                )
                if attempt < len(backoff_times):
                    await asyncio.sleep(backoff)
                    continue
                raise exc

            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                logger.warning(
                    f"[{model}] Malformed JSON response. "
                    f"Using defensive fallback: {type(exc).__name__}"
                )
                raise ValueError(f"Response is not valid JSON: {response_text[:100]}") from exc

        raise RuntimeError("Unreachable retry loop termination")

    @staticmethod
    def _extract_json(response_text: str) -> dict[str, Any]:
        """
        Extract and parse JSON from model response.

        The Modelfile system prompt forces JSON-only output, but we add
        defensive parsing to handle edge cases.

        Args:
            response_text: Raw response text from Ollama.

        Returns:
            dict: Parsed JSON object.

        Raises:
            ValueError: If no valid JSON found in response.
        """
        # Try direct parsing first (most common case)
        try:
            parsed = json.loads(response_text)
            if not isinstance(parsed, dict):
                raise ValueError("Model response JSON is not an object")
            return cast(dict[str, Any], parsed)
        except json.JSONDecodeError:
            pass

        # Defensive: search for JSON object in response
        # (in case Ollama or model included extra text)
        text = response_text.strip()
        if text.startswith("{"):
            try:
                # Find matching closing brace
                brace_count = 0
                for i, char in enumerate(text):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = text[: i + 1]
                            parsed = json.loads(json_str)
                            if not isinstance(parsed, dict):
                                raise ValueError("Model response JSON is not an object")
                            return cast(dict[str, Any], parsed)
            except json.JSONDecodeError:
                pass

        # Final fallback: log error and raise
        logger.error(f"Could not parse JSON from response: {response_text[:200]}")
        raise ValueError(f"Response is not valid JSON: {response_text[:100]}")

    @staticmethod
    def _normalize_confidence(value: Any) -> float:
        """Normalize confidence to float in [0.0, 1.0], defaulting to 0.0."""
        if value is None:
            return 0.0
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.0
        return min(1.0, max(0.0, confidence))

    async def close(self) -> None:
        """Close HTTP client connection."""
        if self._client is not None:
            await self._client.aclose()
