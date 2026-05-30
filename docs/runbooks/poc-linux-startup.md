# AEGIS v0.4 — POC Startup Runbook (Linux)

This runbook covers clean startup and verification of the Node 1 Docker stack on a Linux host,
including the OpenLDAP identity sync pipeline.

---

## Prerequisites

### 1. Kernel setting — OpenSearch memory map

```bash
cat /proc/sys/vm/max_map_count
# Must be ≥ 262144. If lower:
sudo sysctl -w vm.max_map_count=262144
# To persist across reboots:
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 2. Docker version

```bash
docker --version       # Engine ≥ 24
docker compose version # Compose ≥ 2.20
```

### 3. Environment file

The Makefile reads **`.env` at the repo root** (not `docker/node1/.env`).
Copy from the example and fill in your values:

```bash
cp .env.example .env
# Edit .env — replace all CHANGE_ME_USE_VAULT values
```

**Critical — Wazuh password hashes**: the bcrypt hashes in
`docker/node1/wazuh-indexer/internal_users.yml` must match your `.env` values for
`WAZUH_INDEXER_PASSWORD` (admin user) and `WAZUH_DASHBOARD_PASSWORD` (kibanaserver user).
The hashes committed to the repo match the project `.env`.

If you change those passwords, regenerate hashes and update the file **before** first startup:

```bash
docker run --rm wazuh/wazuh-indexer:4.7.5 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
  -p 'YOUR_NEW_PASSWORD' 2>/dev/null | tail -1
# Paste output into internal_users.yml for the appropriate user
# Then: docker compose -f docker/node1/docker-compose.yml --env-file .env down -v
```

### 4. POC LDAP variables in `.env`

For the identity sync pipeline add these to root `.env` (already present in `.env.example`):

```
LDAP_HOST=openldap
LDAP_PORT=389
LDAP_USE_SSL=false
LDAP_BASE_DN=dc=industrie,dc=local
LDAP_BIND_DN=cn=admin,dc=industrie,dc=local
LDAP_BIND_PASSWORD=poc-ldap-admin
LDAP_TIER0_GROUP_DN=cn=Domain Admins,cn=Users,dc=industrie,dc=local
```

---

## Step 1 — Build images (first time or after code changes)

```bash
make docker-build
docker system prune -f   # reclaim build cache — do this after every build
```

---

## Step 2 — Start the main stack

> **Important**: always start from a clean state on first run. Stale OpenSearch
> security indices will reject current passwords if volumes exist from a prior run
> with different passwords.

```bash
make docker-up
```

Monitor until all services reach healthy:

```bash
make docker-ps
# or watch -n5 make docker-ps
```

Expected final state (9 containers):

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

Total time: ~3–5 minutes. The Wazuh indexer must become healthy before the manager
and dashboard can start.

### Quick verification

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy   # 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:15672             # 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/heartbeat  # 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000              # 302
curl -sk -o /dev/null -w "%{http_code}" https://localhost:5601            # 302
```

---

## Step 3 — Start OpenLDAP (POC overlay)

```bash
make docker-poc-up
```

Verify it's running:

```bash
docker ps | grep openldap   # must show Up
```

---

## Step 4 — Seed LDAP (15 assets)

```bash
docker exec -i aegis-poc-openldap-1 ldapadd -c \
  -x -D "cn=admin,dc=industrie,dc=local" -w poc-ldap-admin \
  < scripts/poc/seed_ldap.ldif
```

The `-c` flag continues on errors (safe to re-run if some entries already exist).

Verify 3 tier0 assets are in the `Domain Admins` group:

```bash
docker exec aegis-poc-openldap-1 ldapsearch \
  -x -H ldap://localhost:389 \
  -D "cn=admin,dc=industrie,dc=local" -w poc-ldap-admin \
  -b "dc=industrie,dc=local" "(objectClass=groupOfNames)" cn member \
  2>/dev/null | grep -E "^cn:|^member:"
# Expected: Domain Admins with members DC-01, DC-02, PKI-01
```

---

## Step 5 — Synchronise LDAP → ChromaDB

Publish 15 identity.sync messages via the RabbitMQ management API:

```bash
python3 - <<'EOF'
import urllib.request, json, base64

# Update USER/PASS to match RABBITMQ_USER / RABBITMQ_PASSWORD in .env
RABBIT_URL = "http://localhost:15672/api/exchanges/aegis/aegis.alerts/publish"
USER = "aegis"
PASS = "YOUR_RABBITMQ_PASSWORD"

assets = [
    "DC-01", "DC-02", "PKI-01",
    "SRV-FILE-01", "SRV-PRINT-01", "SRV-BACKUP-01",
    "WS-PROD-01", "WS-PROD-02", "WS-PROD-03",
    "WS-OFFICE-01", "WS-OFFICE-02",
    "PLC-01", "PLC-02", "HMI-01", "SCADA-01",
]

auth = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}

success = 0
for asset in assets:
    payload = {
        "properties": {},
        "routing_key": "identity.sync",
        "payload": json.dumps({"asset_id": asset}),
        "payload_encoding": "string",
    }
    req = urllib.request.Request(RABBIT_URL, json.dumps(payload).encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        if json.loads(r.read()).get("routed"):
            success += 1
            print(f"  OK: {asset}")
        else:
            print(f"  NOT ROUTED: {asset}")

print(f"\nPublished {success}/{len(assets)}")
EOF
```

Wait ~10 seconds then check middleware logs — there should be **no** `WARNING` lines:

```bash
docker compose -f docker/node1/docker-compose.yml --env-file .env logs --tail=30 middleware \
  | grep -v posthog
```

---

## Step 6 — Verify ChromaDB count = 15

ChromaDB requires a UUID to query by name, so extract it first:

```bash
COLL_ID=$(curl -s http://localhost:8000/api/v1/collections \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

# Count
curl -s "http://localhost:8000/api/v1/collections/$COLL_ID/count"
# Expected: 15 (or more if Step 5 was run multiple times — each upsert is idempotent)

# Spot-check tier0 detection
curl -s -X POST "http://localhost:8000/api/v1/collections/$COLL_ID/get" \
  -H "Content-Type: application/json" \
  -d '{"ids":["DC-01","DC-02","PKI-01"]}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for i, m in zip(d['ids'], d['metadatas']):
    print(i, m.get('asset_criticality'))
"
# Expected: DC-01 tier0 / DC-02 tier0 / PKI-01 tier0
```

---

## Step 7 — Verify Raspberry Pi connectivity (Partie C prerequisite)

The Pi must be reachable on WireGuard IP `10.0.0.1` with Ollama listening on `0.0.0.0:11434`.

```bash
# curl is not installed in the middleware image — use Python instead
docker exec aegis-node1-middleware-1 python3 -c "
import urllib.request, json
r = urllib.request.urlopen('http://10.0.0.1:11434/api/tags', timeout=5)
for m in json.loads(r.read()).get('models', []):
    print(m['name'])
"
# Expected: tinyllama-aegis and mistral-aegis in the list
```

If the models are not listed, run Partie C steps first (see below).

---

## Step 8 — Kali attack simulation

Run from the Kali machine on the same network:

```bash
# SSH brute force (triggers Wazuh rule 5710/5712)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10

# Port scan (triggers Wazuh rule 1400x)
nmap -sS -O 192.168.1.10

# Sudo abuse (run on the monitored host itself)
sudo su -

# Tier0 asset alert simulation — publish a fake Wazuh alert via RabbitMQ
python3 - <<'ALERT'
import urllib.request, json, base64
RABBIT_URL = "http://localhost:15672/api/exchanges/aegis/aegis.alerts/publish"
auth = base64.b64encode(b"aegis:YOUR_RABBITMQ_PASSWORD").decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}
alert = {
    "id": "test-001", "timestamp": "2026-05-24T12:00:00Z",
    "rule": {"level": 12, "description": "Multiple authentication failures"},
    "source_ip": "DC-01", "destination_ip": "192.168.1.20",
    "agent": {"name": "DC-01"},
}
payload = {
    "properties": {}, "routing_key": "alert.raw",
    "payload": json.dumps(alert), "payload_encoding": "string",
}
req = urllib.request.Request(RABBIT_URL, json.dumps(payload).encode(), headers, method="POST")
print(json.loads(urllib.request.urlopen(req, timeout=5).read()))
ALERT
```

---

## Step 9 — Monitor

```bash
# Live middleware logs
docker compose -f docker/node1/docker-compose.yml --env-file .env logs -f middleware \
  | grep -v posthog

# Grafana dashboard
open http://localhost:3000   # login: GF_SECURITY_ADMIN_USER / GF_SECURITY_ADMIN_PASSWORD

# RabbitMQ queue depths
open http://localhost:15672  # Queues tab
```

---

## Partie C — Raspberry Pi setup (manual, done once)

Replace `PI_USER` and `PI_IP` with your Pi's username and WireGuard IP (e.g. `10.0.0.1`).

```bash
# From the dev machine — copy Modelfiles to the Pi
scp docs/modelfiles/Modelfile.slm-tinyllama PI_USER@PI_IP:~/
scp docs/modelfiles/Modelfile.llm-mistral   PI_USER@PI_IP:~/

# SSH into the Pi
ssh PI_USER@PI_IP

# Check base models are present
ollama list
# Required: tinyllama:latest, mistral:7b-instruct-q4_K_M
```

**Make Ollama listen on all interfaces** (required for Node1 to reach it via WireGuard).
`systemctl edit` may silently discard an empty file — write the override directly:

```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d/
sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF
sudo systemctl daemon-reload
sudo systemctl restart ollama

# Verify — must show *:11434 (all interfaces)
ss -tlnp | grep 11434
```

```bash
# Create AEGIS-tuned model variants
ollama create tinyllama-aegis -f ~/Modelfile.slm-tinyllama
ollama create mistral-aegis   -f ~/Modelfile.llm-mistral

# Verify (from the Pi)
ollama list
# Must include: tinyllama-aegis, mistral-aegis
```

**Verify from Node1 host** (curl is not installed in the middleware container):

```bash
python3 -c "
import urllib.request, json
r = urllib.request.urlopen('http://PI_IP:11434/api/tags', timeout=5)
for m in json.loads(r.read()).get('models', []):
    print(m['name'])
"
# Must include: tinyllama-aegis, mistral-aegis
```

---

## Access URLs

| Service | URL | Credentials |
|---|---|---|
| Wazuh Dashboard | https://localhost:5601 | admin / `WAZUH_API_PASSWORD` |
| Grafana | http://localhost:3000 | `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` |
| Prometheus | http://localhost:9090 | — |
| RabbitMQ management | http://localhost:15672 | `RABBITMQ_USER` / `RABBITMQ_PASSWORD` |
| ChromaDB | http://localhost:8000 | — |
| phpLDAPadmin (POC) | http://localhost:8080 | cn=admin,dc=industrie,dc=local / `poc-ldap-admin` |

---

## Teardown

```bash
# Stop POC overlay
make docker-poc-down

# Stop main stack (preserves volumes)
make docker-down

# Full teardown including volumes (required if passwords changed)
docker compose -f docker/node1/docker-compose.yml --env-file .env down -v

# Reclaim space
docker system prune -f
```

---

## Troubleshooting

### Wazuh Dashboard returns 503

**Cause**: `kibanaserver` hash in `internal_users.yml` does not match `WAZUH_DASHBOARD_PASSWORD`.
OpenSearch caches the security index from first startup — updating the file alone is not enough.

**Fix**: update the hash, run `down -v`, then `up`.

### LDAP sync shows "Failed to sync asset, fallback data applied"

**Cause**: one of three ldap3 2.9.1 bugs on Linux, all fixed in the current codebase:

| Bug | Symptom | Fix applied |
|---|---|---|
| `struct.error` on `Connection()` | `auto_bind=True` triggers binary pack with wrong args | Use `AUTO_BIND_NO_TLS` |
| `struct.error` on socket recv timeout | `receive_timeout` is float, `pack('LL',...)` requires int | Cast to `int()` |
| `memberOf` missing | Plain OpenLDAP without `memberof` overlay has no `memberOf` attribute | Reverse `(member=<DN>)` search on the tier0 group |

If you still see this warning, check that the middleware image was rebuilt after the latest code change:

```bash
make docker-build && docker system prune -f
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware
```

### Wazuh Indexer healthcheck never passes

On Linux, OpenSearch binds to IPv6 (`tcp6`). The healthcheck already covers both:

```yaml
grep -q ':23F0' /proc/net/tcp /proc/net/tcp6 2>/dev/null || exit 1
```

Port `9200` hex = `23F0`. Check which address is bound:

```bash
docker exec aegis-node1-wazuh.indexer-1 cat /proc/net/tcp6 | grep 23F0
```

### Ports 15672 / 8000 / 9090 not reachable from host

Services connected only to `aegis-internal` (marked `internal: true`) cannot publish ports.
They must also be connected to `aegis-monitoring`. Already fixed in current `docker-compose.yml`.

### ChromaDB count API returns "InvalidUUID"

The ChromaDB v0.4 API requires a UUID, not the collection name. Use:

```bash
COLL_ID=$(curl -s http://localhost:8000/api/v1/collections \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
curl -s "http://localhost:8000/api/v1/collections/$COLL_ID/count"
```

### `ldapadd` stops at first error

Add `-c` to continue on existing entries:

```bash
ldapadd -c -x -D "cn=admin,dc=industrie,dc=local" -w poc-ldap-admin < seed.ldif
```

### make docker-up starts from wrong .env

The Makefile reads **root `.env`**, not `docker/node1/.env`. All env vars (including LDAP)
must be in the repo root `.env`.

### Wazuh Dashboard — "No API available to connect"

**Cause**: `docker/node1/wazuh-dashboard/wazuh.yml` still has the placeholder password
`CHANGE_ME_USE_VAULT` instead of your actual `WAZUH_API_PASSWORD`.

**Fix** (do not commit — local only):

```bash
# Replace the placeholder with your real WAZUH_API_PASSWORD
sed -i "s/CHANGE_ME_USE_VAULT/$(grep ^WAZUH_API_PASSWORD= .env | cut -d= -f2)/" \
  docker/node1/wazuh-dashboard/wazuh.yml

docker compose -f docker/node1/docker-compose.yml --env-file .env restart wazuh.dashboard
```

### SLM (TinyLlama) timeouts on Raspberry Pi

**Cause**: default `SLM_TIMEOUT=10` is too short for a cold-start on a Pi.
TinyLlama typically responds in 15–20 s on first call, then 1–3 s with `keep_alive` active.

**Fix**: set in root `.env`:

```
SLM_TIMEOUT=30
LLM_TIMEOUT=180
```

Then rebuild and restart middleware:

```bash
make docker-build && docker system prune -f
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware
```
