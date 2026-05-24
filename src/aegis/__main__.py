"""
AEGIS entry point: main application runner.

Loads environment variables from .env and starts the RabbitMQ consumer.
The consumer listens to aegis.wazuh.alerts queue indefinitely.

Usage:
    python -m aegis

Environment variables required:
    RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD
    RABBITMQ_QUEUE
    OLLAMA_BASE_URL, SLM_MODEL, LLM_MODEL, SLM_TIMEOUT, LLM_TIMEOUT
    SUSPICION_THRESHOLD
    CHROMADB_HOST, CHROMADB_PORT
    SHUFFLE_WEBHOOK_URL
    LOG_LEVEL

See .env.example and docs/raspberrypi-ollama-setup.md for details.
"""

import asyncio
import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv
from prometheus_client import start_http_server

from aegis.middleware.consumer import RabbitMQConsumer
from aegis.middleware.consumer_identity import build_identity_consumer_from_env
from aegis.monitoring.metrics import MetricsCollector
from aegis.vault.loader import load_secrets_to_env

# Load environment variables from .env
load_dotenv()


def setup_logging() -> None:
    """
    Configure Python logging with rotating file handler + console output.

    Format: JSON structured logs for easy parsing and ingestion.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level_int = getattr(logging, log_level, logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level_int)

    # Avoid duplicate handlers if setup_logging is called more than once.
    if root_logger.handlers:
        root_logger.handlers.clear()

    # Console handler (stdout)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level_int)
    console_formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler (rotating, max 10MB per file, 5 files)
    explicit_log_file = os.getenv("LOG_FILE")
    if explicit_log_file:
        log_file = Path(explicit_log_file)
    else:
        home_dir = Path.home()
        if (
            str(home_dir) == "/nonexistent"
            or not home_dir.exists()
            or not os.access(home_dir, os.W_OK)
        ):
            log_file = Path(tempfile.gettempdir()) / "aegis.log"
        else:
            log_file = home_dir / "aegis.log"

    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setLevel(log_level_int)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    except OSError as exc:
        logging.warning(f"File logging disabled: {exc}")

    logging.info(f"Logging initialized at level {log_level}")


async def main() -> None:
    """
    Main entry point: initialize consumer and start listening.

    Reads all configuration from environment variables.
    Runs indefinitely until interrupted (SIGTERM/SIGINT).
    """
    logging.info("=" * 80)
    logging.info("AEGIS v0.4.0 - Sovereign SOC Orchestrator (On-Premise AI)")
    logging.info("=" * 80)

    start_http_server(8080)
    metrics_collector = MetricsCollector()
    logging.info("Prometheus metrics endpoint started on port 8080")

    # Load configuration from environment
    rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
    rabbitmq_port = int(os.getenv("RABBITMQ_PORT", "5672"))
    rabbitmq_user = os.getenv("RABBITMQ_USER", "guest")
    rabbitmq_password = os.getenv("RABBITMQ_PASSWORD", "guest")
    rabbitmq_queue = os.getenv("RABBITMQ_QUEUE", "aegis.wazuh.alerts")

    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://10.0.0.1:11434")
    slm_timeout = float(os.getenv("SLM_TIMEOUT", "10.0"))
    llm_timeout = float(os.getenv("LLM_TIMEOUT", "45.0"))
    suspicion_threshold = float(os.getenv("SUSPICION_THRESHOLD", "0.5"))

    chromadb_host = os.getenv("CHROMADB_HOST", "localhost")
    chromadb_port = int(os.getenv("CHROMADB_PORT", "8000"))

    shuffle_webhook_url = os.getenv("SHUFFLE_WEBHOOK_URL", "http://shuffle:3001/api/v1/hooks/")

    # Log configuration (without secrets)
    logging.info(
        f"Configuration loaded: "
        f"RabbitMQ={rabbitmq_host}:{rabbitmq_port}, "
        f"Ollama={ollama_base_url}, "
        f"ChromaDB={chromadb_host}:{chromadb_port}, "
        f"Shuffle=******, "
        f"suspicion_threshold={suspicion_threshold}"
    )

    import urllib.parse

    _shuffle_host = urllib.parse.urlparse(shuffle_webhook_url).hostname or ""
    if _shuffle_host == "shuffle":
        logging.warning(
            "SHUFFLE_WEBHOOK_URL points to 'shuffle' hostname — "
            "ensure the stack is started with --profile full or override SHUFFLE_WEBHOOK_URL"
        )

    # Initialize consumer
    consumer = RabbitMQConsumer(
        rabbitmq_host=rabbitmq_host,
        rabbitmq_port=rabbitmq_port,
        rabbitmq_user=rabbitmq_user,
        rabbitmq_password=rabbitmq_password,
        queue_name=rabbitmq_queue,
        ollama_base_url=ollama_base_url,
        chromadb_host=chromadb_host,
        chromadb_port=chromadb_port,
        shuffle_webhook_url=shuffle_webhook_url,
        metrics=metrics_collector,
        suspicion_threshold=suspicion_threshold,
        slm_timeout=slm_timeout,
        llm_timeout=llm_timeout,
    )

    identity_consumer = build_identity_consumer_from_env()

    # Start both consumers concurrently — triage pipeline + identity sync
    try:
        await asyncio.gather(
            consumer.start(),
            identity_consumer.start(),
        )
    except KeyboardInterrupt:
        logging.info("Interrupted by user. Gracefully shutting down...")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    load_secrets_to_env()
    setup_logging()
    asyncio.run(main())
