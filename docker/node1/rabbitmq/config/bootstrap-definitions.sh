#!/bin/sh
set -eu

RABBITMQ_API_URL="http://rabbitmq:15672/api"
DEFINITIONS_FILE="/bootstrap/definitions.json"

if [ -z "${RABBITMQ_USER:-}" ] || [ -z "${RABBITMQ_PASSWORD:-}" ]; then
  echo "RABBITMQ_USER and RABBITMQ_PASSWORD must be set"
  exit 1
fi

echo "Waiting for RabbitMQ management API..."
for i in $(seq 1 60); do
  if curl -fsS -u "$RABBITMQ_USER:$RABBITMQ_PASSWORD" "$RABBITMQ_API_URL/overview" >/dev/null; then
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "RabbitMQ management API did not become ready in time"
    exit 1
  fi
done

echo "Applying definitions from $DEFINITIONS_FILE"
curl -fsS -u "$RABBITMQ_USER:$RABBITMQ_PASSWORD" \
  -H "content-type: application/json" \
  -X POST \
  --data-binary "@$DEFINITIONS_FILE" \
  "$RABBITMQ_API_URL/definitions"

echo "Definitions applied successfully"
