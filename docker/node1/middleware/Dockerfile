FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

COPY . /app

# hadolint ignore=DL3013
RUN pip install --upgrade pip && pip install --no-cache-dir -e /app

USER appuser

ENTRYPOINT ["python", "-m", "aegis"]
