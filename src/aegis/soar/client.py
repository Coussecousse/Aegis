"""
Shuffle SOAR webhook client for AEGIS report delivery.

Sends completed AegisReport to Shuffle SOAR via HTTP POST.
Handles:
- Webhook authentication (bearer token in SHUFFLE_WEBHOOK_URL)
- Retry logic (3 attempts on HTTP errors)
- JSON serialization with UUID handling
- Zero cloud calls (on-premise Shuffle instance)
"""

import asyncio
import json
import logging
from typing import Any

import httpx

from aegis.middleware.models import AegisReport

logger = logging.getLogger(__name__)


class ShuffleClient:
    """Async HTTP client for Shuffle SOAR webhook delivery."""

    def __init__(self, webhook_url: str) -> None:
        """
        Initialize Shuffle client.

        Args:
            webhook_url: Full webhook URL from Shuffle SOAR
                        (e.g., http://shuffle:3001/api/v1/hooks/HOOK_ID).
        """
        self.webhook_url = webhook_url
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ShuffleClient":
        """Context manager entry."""
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        if self._client is not None:
            await self._client.aclose()

    async def send_report(self, report: AegisReport) -> bool:
        """
        Send AEGIS report to Shuffle SOAR via webhook.

        Attempts up to 3 times with exponential backoff: 1s, 2s, 4s.
        Serializes AegisReport to JSON (handles UUID encoding).

        Args:
            report: Complete AegisReport to send.

        Returns:
            bool: True if sent successfully, False if all retries failed.
        """
        logger.debug(f"Sending report {report.alert_id} to Shuffle SOAR")

        # Serialize report to JSON (custom encoder for UUID)
        try:
            payload = json.loads(report.model_dump_json())  # Pydantic handles UUID serialization
        except Exception as e:
            logger.error(f"Failed to serialize report: {e}")
            return False

        backoff_times = [1.0, 2.0, 4.0]  # Exponential backoff

        for attempt, backoff in enumerate(backoff_times, start=1):
            try:
                logger.debug(
                    f"[Shuffle] Attempt {attempt}/3 - sending report " f"{report.alert_id}"
                )

                if self._client is None:
                    self._client = httpx.AsyncClient(timeout=30.0)

                response = await self._client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30.0,
                )
                response.raise_for_status()

                logger.info(
                    f"[Shuffle] Report {report.alert_id} sent successfully "
                    f"(status: {response.status_code})"
                )
                return True

            except (TimeoutError, httpx.HTTPError) as e:
                logger.warning(f"[Shuffle] Attempt {attempt}/3 - ERROR: {type(e).__name__}: {e}")
                if attempt < len(backoff_times):
                    logger.debug(f"Retrying in {backoff}s...")
                    await asyncio.sleep(backoff)
                continue

        # All retries exhausted
        logger.error(f"[Shuffle] Failed to send report {report.alert_id} after 3 attempts")
        return False

    async def close(self) -> None:
        """Close HTTP client connection."""
        if self._client is not None:
            await self._client.aclose()
