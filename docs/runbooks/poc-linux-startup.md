# AEGIS v0.4 — POC Startup Runbook (Linux)

This runbook covers clean startup and verification of the Node 1 Docker stack on a Linux host.
Run through it end-to-end before any POC demonstration.

---

## Prerequisites

### 1. Kernel setting — OpenSearch memory map

The Wazuh Indexer (OpenSearch) requires a large virtual memory map count.
Check and set it before starting the stack:

```bash
cat /proc/sys/vm/max_map_count
# Must be ≥ 262144. If lower:
sudo sysctl -w vm.max_map_count=262144
# To persist across reboots, add to /etc/sysctl.conf:
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 2. Docker version

```bash
docker --version       # Engine ≥ 24
docker compose version # Compose ≥ 2.20
```

### 3. Environment file

The stack reads `docker/node1/.env`. If it does not exist yet, copy from the
example template at the root and fill in your values:

```bash
cp .env.example docker/node1/.env
# Edit docker/node1/.env — replace all CHANGE_ME_USE_VAULT values
```

**Critical**: the bcrypt hashes in `docker/node1/wazuh-indexer/internal_users.yml` must
match your `.env` values for `WAZUH_INDEXER_PASSWORD` (admin user) and
`WAZUH_DASHBOARD_PASSWORD` (kibanaserver user). The hashes checked into the
repo were generated from the passwords in the project `.env`.

If you change those passwords, regenerate hashes via the Wazuh tool and update
the file **before** first startup:

```bash
# Start the indexer once, generate the hash, stop it
docker run --rm wazuh/wazuh-indexer:4.7.5 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
  -p 'YOUR_NEW_PASSWORD' 2>/dev/null | tail -1
# Paste the output into internal_users.yml for the appropriate user
# Then do a clean start: docker compose down -v && docker compose up -d
```

---

## Build images (first time or after code changes)

```bash
make docker-build
```

---

## Starting the stack

> **Important**: always start from a clean state. If volumes from a previous run
> exist, stale OpenSearch security indices will reject the current passwords.

```bash
# From the repo root:
make docker-up
# Equivalent to:
# docker compose -f docker/node1/docker-compose.yml --env-file docker/node1/.env up -d
```

For full mode (includes Shuffle SOAR):

```bash
make docker-up-full
```

---

## Monitoring startup

The Wazuh Indexer takes ~60 seconds to become healthy before the Dashboard and
Manager can start. Watch progress with:

```bash
make docker-ps
# or:
docker compose -f docker/node1/docker-compose.yml --env-file docker/node1/.env ps
```

Expected final state (core mode — 9 containers):

| Service | Status |
|---|---|
| wazuh.indexer | healthy |
| wazuh.manager | healthy |
| wazuh.dashboard | healthy |
| rabbitmq | healthy |
| rabbitmq-bootstrap | exited (0) |
| chromadb | healthy |
| middleware | up |
| collector | up |
| prometheus | up |
| grafana | up |

Total time from `up -d` to all services healthy: approximately 3–5 minutes.

---

## Verification

Once all services show healthy, run these HTTP checks from the host:

```bash
# Prometheus — must return 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy

# RabbitMQ management — must return 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:15672

# ChromaDB — must return 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/heartbeat

# Grafana — must return 302 (redirect to login)
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000

# Wazuh Dashboard — must return 302 (redirect to login)
curl -sk -o /dev/null -w "%{http_code}" https://localhost:5601
```

All five must return 200 or 302. A 503 from the Wazuh Dashboard means the
`kibanaserver` password in `internal_users.yml` does not match `WAZUH_DASHBOARD_PASSWORD`
in `.env` — see Troubleshooting below.

---

## Access URLs and credentials

| Service | URL | Credentials |
|---|---|---|
| Wazuh Dashboard | https://localhost:5601 | admin / `WAZUH_API_PASSWORD` from .env |
| Grafana | http://localhost:3000 | `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` from .env |
| Prometheus | http://localhost:9090 | — (no auth) |
| RabbitMQ management | http://localhost:15672 | `RABBITMQ_USER` / `RABBITMQ_PASSWORD` from .env |
| ChromaDB | http://localhost:8000 | — (no auth) |

> The Wazuh Dashboard login user is `admin`. The password is `WAZUH_API_PASSWORD`
> (not `WAZUH_INDEXER_PASSWORD`). The Wazuh API auth is separate from the indexer auth.

---

## POC stack (OpenLDAP identity connector)

After the main stack is healthy, start the POC overlay:

```bash
make docker-poc-up
# Equivalent to:
# docker compose -f docker/node1/docker-compose.poc.yml --env-file docker/node1/.env up -d
```

Stop it independently:

```bash
make docker-poc-down
```

---

## Stopping the stack

Normal stop (preserves data volumes, fast restart):

```bash
docker compose -f docker/node1/docker-compose.yml --env-file docker/node1/.env down
```

Full teardown including all volumes (required after password changes):

```bash
docker compose -f docker/node1/docker-compose.yml --env-file docker/node1/.env down -v
```

---

## Troubleshooting

### Wazuh Dashboard returns 503

**Cause**: the `kibanaserver` bcrypt hash in `internal_users.yml` does not match
`WAZUH_DASHBOARD_PASSWORD` in `.env`. OpenSearch caches the old hash in its
security index, so updating only `internal_users.yml` is not enough after first run.

**Fix**:
1. Update `internal_users.yml` with a hash generated from the correct password
   (see the hash generation command in Prerequisites).
2. Run `docker compose down -v` to wipe the security index from the volume.
3. Run `docker compose up -d` to start fresh.

The same applies to the `admin` user hash vs `WAZUH_INDEXER_PASSWORD`.

### Wazuh Indexer healthcheck never passes

**Cause**: on Linux, OpenSearch binds to IPv6 (`tcp6`) rather than IPv4 (`tcp`).
The healthcheck in this repo already covers both:

```yaml
grep -q ':23F0' /proc/net/tcp /proc/net/tcp6 2>/dev/null || exit 1
```

If you see the indexer stuck at `health: starting`, check which address it bound to:

```bash
docker exec aegis-node1-wazuh.indexer-1 cat /proc/net/tcp6 | grep 23F0
```

Port `9200` in hex is `23F0`. If the line appears there, the healthcheck should pass.

### Ports 15672 / 8000 / 9090 not reachable from host

**Cause**: services connected only to the `aegis-internal` network (marked
`internal: true`) cannot publish ports to the host. The fix is to also connect
the service to `aegis-monitoring` (the non-internal bridge) and add a `ports`
mapping. This is already done in the current `docker-compose.yml`.

### wazuh.manager or wazuh.dashboard stuck at `health: starting`

Both depend on `wazuh.indexer: condition: service_healthy`. If the indexer
takes longer than usual to initialize (fresh volume + security index creation),
the dependent containers will stay in `health: starting` until it becomes
healthy. Wait up to 5 minutes before investigating further.

### Middleware/collector logs show connection refused

The middleware and collector start after `rabbitmq-bootstrap` completes. If
RabbitMQ is still initializing, they retry. Check with:

```bash
docker compose -f docker/node1/docker-compose.yml --env-file docker/node1/.env logs middleware collector
```

---

## Linux-specific notes

- The Docker user running the stack must have access to Docker socket (`sudo usermod -aG docker $USER`).
- The `HOME` directory for the `wazuh` system user inside containers may be
  `/nonexistent`. AEGIS handles this gracefully by falling back to `tmpdir` for log files.
- IPv6 must not be disabled system-wide, as OpenSearch binds to `::` on Linux Docker Engine.
