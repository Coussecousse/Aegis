FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

COPY . /app

RUN pip install --upgrade pip && pip install --no-cache-dir -e /app

USER appuser

ENTRYPOINT ["python", "-m", "aegis"]
