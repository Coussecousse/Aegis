# AEGIS — Getting Started

How to bring AEGIS up from scratch, in order, and what to watch out for. For the
full POC walkthrough (Juice Shop target, Kali attacks, Shuffle) see
[runbooks/poc-linux-startup.md](runbooks/poc-linux-startup.md); for Node 2 (the Pi)
see [raspberrypi-ollama-setup.md](raspberrypi-ollama-setup.md). All `make` targets
are listed in [makefile.md](makefile.md).

## Topology

- **Node 1 (controller VM)** — all Docker services (Wazuh, RabbitMQ, PostgreSQL, the
  middleware + collector, Shuffle, Prometheus/Grafana).
- **Node 2 (Raspberry Pi)** — Ollama only (SLM triage + LLM reports), reached over
  the LAN/WireGuard. AEGIS makes **zero cloud calls** — all inference is local.

## Prerequisites

- Python 3.12, Docker Engine + Compose, `pre-commit`.
- **Linux:** `vm.max_map_count` ≥ 262144 (Wazuh indexer / OpenSearch). Check with
  `cat /proc/sys/vm/max_map_count`; if lower: `sudo sysctl -w vm.max_map_count=262144`
  (persist in `/etc/sysctl.conf`).
- A reachable **Node 2** running Ollama with the two models created from
  `docs/modelfiles/` (`qwen25-aegis`, `mistral-aegis`).

## Setup order

1. **Secrets** — `cp .env.example .env`, then fill every `CHANGE_ME` value. In dev,
   secrets live in `.env` (git-ignored); in prod they come from HashiCorp Vault.
   Never commit secrets — `detect-secrets` blocks it.
2. **Build** the middleware + collector images: `make docker-build`.
3. **Start Node 1** — `make docker-up` (core) or `make docker-up-full` (with Shuffle).
   Wait until `make docker-ps` shows services `healthy`.
4. **Identity source (UEBA)** — start the LDAP overlay (`make docker-poc-up`) and seed
   it, then sync identities into PostgreSQL. UEBA needs a working **identity connector**
   (see gotchas).
5. **Attack target (POC)** — `make docker-juiceshop-up` exposes Juice Shop + nginx on
   `:9080`; point the Wazuh agent at the nginx access log (see the POC runbook).
6. **Verify** — Wazuh Dashboard `https://localhost:5601`, Grafana `http://localhost:3000`,
   RabbitMQ `http://localhost:15672`; Shuffle `http://localhost:3001` (full mode).

## Things to watch out for

- **Identity connector is required for UEBA.** The middleware enriches alerts from an
  identity store via the `BaseIdentityConnector` seam (LDAP today). Without a reachable
  store, assets fall back to a default `tier2` profile (it degrades gracefully but you
  lose criticality/behaviour context). Make sure the connector config in `.env` points
  at a live store and that the LDAP→PostgreSQL sync has run. See [ueba.md](ueba.md).
- **Node 2 must be reachable and the models created.** If Ollama is down or the
  `qwen25-aegis` / `mistral-aegis` models are missing, triage/analysis fail. Confirm
  with the connectivity check in the Pi setup doc.
- **Shuffle webhook.** Set `SHUFFLE_WEBHOOK_URL` to your Shuffle hook so reports are
  delivered; otherwise the analysis stage produces reports that go nowhere.
- **`WAZUH_MIN_LEVEL`.** Controls which alerts enter the pipeline. Level 6 lets web
  attacks (XSS/traversal) in; higher values filter more aggressively.
- **Changing a RabbitMQ queue's arguments** (e.g. TTL) requires deleting + recreating
  the queue **and restarting the middleware**, or the consumer stays bound to the old
  queue. See the reliability section of the POC runbook.
- **Passwords changed after first boot?** Run `make docker-clean` (removes volumes) and
  start again — Wazuh/OpenSearch bake credentials into their data volumes.

## Quality gate (before every commit)

`make lint && make format && make typecheck && make test && make pre-commit-all`.
