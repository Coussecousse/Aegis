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
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

from aegis.middleware.consumer import RabbitMQConsumer

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
    log_file = Path(os.getenv("LOG_FILE", str(Path.home() / "aegis.log")))
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

    logging.info(f"Logging initialized at level {log_level}")


async def main() -> None:
    """
    Main entry point: initialize consumer and start listening.

    Reads all configuration from environment variables.
    Runs indefinitely until interrupted (SIGTERM/SIGINT).
    """
    logging.info("=" * 80)
    logging.info("AEGIS v0.3.0 - Sovereign SOC Orchestrator (On-Premise AI)")
    logging.info("=" * 80)

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
        suspicion_threshold=suspicion_threshold,
        slm_timeout=slm_timeout,
        llm_timeout=llm_timeout,
    )

    # Start consuming
    try:
        await consumer.start()
    except KeyboardInterrupt:
        logging.info("Interrupted by user. Gracefully shutting down...")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
