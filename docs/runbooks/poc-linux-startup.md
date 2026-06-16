# AEGIS — POC Startup (Linux)

End-to-end POC walkthrough: bring up the stack, seed identities, attack a realistic
target (Juice Shop) from Kali, and watch AEGIS react. General setup and gotchas are in
[getting-started.md](../getting-started.md); the Pi/Ollama node in
[raspberrypi-ollama-setup.md](../raspberrypi-ollama-setup.md); every `make` target in
[makefile.md](../makefile.md).

> **Prereqs:** Docker, a filled `.env` (`cp .env.example .env`), and on Linux
> `vm.max_map_count ≥ 262144` (`sudo sysctl -w vm.max_map_count=262144`). A reachable
> Pi running `qwen25-aegis` (SLM) and `mistral-aegis` (LLM).

## 1. Start the core stack

```bash
make docker-build      # first run / after code changes
make docker-up         # core (no Shuffle); or `make docker-up-full` with Shuffle
make docker-ps         # wait until services are healthy
```

## 2. Seed identities (UEBA)

```bash
make docker-poc-up                                    # OpenLDAP overlay
docker exec -i aegis-poc-openldap-1 ldapadd -c \
  -x -D "cn=admin,dc=industrie,dc=local" -w poc-ldap-admin \
  < scripts/poc/seed_ldap.ldif                        # 15 assets (3 tier0)
```

Sync LDAP → ChromaDB by publishing one `identity.sync` per asset to the
`aegis.alerts` exchange (routing key `identity.sync`), then verify:

```bash
COLL_ID=$(curl -s http://localhost:8000/api/v1/collections \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
curl -s "http://localhost:8000/api/v1/collections/$COLL_ID/count"   # expect 15
```

The DC/PKI assets must come back `tier0`. See [ueba.md](../ueba.md) for the connector.

## 3. Verify the Pi

```bash
docker exec aegis-node1-middleware-1 python3 -c "
import urllib.request, json
for port in (11434, 11435):
    r = urllib.request.urlopen(f'http://10.0.0.1:{port}/api/tags', timeout=5)
    print(port, [m['name'] for m in json.loads(r.read()).get('models', [])])"
# expect qwen25-aegis on 11434, mistral-aegis on 11435
```

## 4. Attack target (Juice Shop)

```bash
make docker-juiceshop-up      # Juice Shop + nginx on :9080
```

Point the Wazuh agent at the nginx access log so web attacks are detected:

```xml
<!-- /var/ossec/etc/ossec.conf, then: sudo systemctl restart wazuh-agent -->
<localfile>
  <log_format>apache</log_format>
  <location>/ABS/PATH/TO/REPO/docker/node1/juice-shop/logs/access.log</location>
</localfile>
```

## 5. Attacks from Kali (target = Node 1 LAN IP, port 9080)

Rules observed on Juice Shop via nginx (decoder `web-accesslog`):

| Attack | Tool | Rule(s) | Level |
|---|---|---|---|
| SQL injection | `sqlmap` / `?q=...UNION/OR/DROP...` | 31103, 31164 | 7 / 6 |
| XSS / web attack (HTTP 200) | `?q=<script>`, `<img onerror>` | 31106 | 6 |
| Path traversal / LFI | `?file=../../etc/passwd`, `/iisadmpwd/..%c0%af..` | 31104, 31106 | 6 |
| Web vuln scan | `nikto` | web family 31100-31199 | 6-7 |
| Port scan | `nmap -A` | HIDS (40xxx) | 6-8 |
| SSH brute force | `hydra ssh://...` | 5710, 5712 | 10 |

```bash
TARGET=<NODE1_LAN_IP>
nikto -h http://$TARGET:9080 -Tuning 9 -maxtime 120s
sqlmap -u "http://$TARGET:9080/rest/products/search?q=test" --batch --level 2 --risk 2 --threads 4
nmap -A -T4 $TARGET
```

**Mise en tension (Phase 2 — load):** sustained varied flood.

```bash
TARGET=<NODE1_LAN_IP>
for i in $(seq 1 200); do
  curl -s -o /dev/null "http://$TARGET:9080/rest/products/search?q=1%27%20OR%20%271%27=%271"
  curl -s -o /dev/null "http://$TARGET:9080/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  curl -s -o /dev/null "http://$TARGET:9080/?file=../../../../etc/passwd"
done
```

`WAZUH_MIN_LEVEL=6` lets XSS/traversal in. The attacker `srcip` (Kali) is recorded
distinct from the monitored host. Measured load behaviour and KPIs:
[benchmarks/README.md §3](../benchmarks/README.md).

## 6. Observe AEGIS react

```bash
docker logs -f aegis-node1-middleware-1 | grep -v posthog   # pipeline events
# Grafana http://localhost:3000  | RabbitMQ http://localhost:15672 (queue depths)
```

## 7. Shuffle SOAR (full mode)

`make docker-up-full` starts Shuffle; create the `AEGIS Alerts` workflow with a Webhook
trigger and copy its hook id. Two gotchas:

- The middleware runs inside Docker, so set `SHUFFLE_WEBHOOK_URL` to the **backend**:
  `http://shuffle-backend:5001/api/v1/hooks/<hook-id>` (not the `:3001` frontend URL),
  then recreate the middleware.
- The `shuffle-apps` / workflows live in volumes that don't survive `down -v` / prune —
  reload apps and re-import the workflow if they vanish.

See [soar-response-actions.md](../soar-response-actions.md) for the response model.

## 8. Access URLs & teardown

| Service | URL |
|---|---|
| Wazuh Dashboard | `https://localhost:5601` |
| Grafana | `http://localhost:3000` |
| RabbitMQ mgmt | `http://localhost:15672` |
| Shuffle (full mode) | `http://localhost:3001` |

```bash
make docker-juiceshop-down && make docker-poc-down
make docker-down            # stop (keep volumes)
make docker-clean           # stop + remove volumes (required after a password change)
```

## Message reliability — queue TTL, dead-letter & overload

AEGIS must never *silently* lose an alert. Flow: collector → `aegis.triage` →
(escalated) → `aegis.reports` → analysis. Both queues are **durable**, messages
**persistent** (`delivery_mode=2`), so a broker restart loses nothing.

- **TTL:** `aegis.triage` and `aegis.reports` carry a **1 h** `x-message-ttl` +
  `x-max-length=10000`.
- **Dead-letter:** both set `x-dead-letter-exchange=aegis.alerts` /
  `routing-key=alert.dead` → the durable **`aegis.deadletter`** queue.

**Under overload** (the Pi analyses ~6–9 min/report, ~7–10/h), the backlog builds; an
alert that can't be processed within 1 h is **parked in `aegis.deadletter`** —
persistent, inspectable, **not discarded**. This is a SOC "parking lot", not loss. The
limit is compute capacity, not reliability (see [benchmarks/README.md §3](../benchmarks/README.md)).

```bash
# how many alerts are parked, and why (x-death reason / origin queue):
curl -s -u "$RABBITMQ_USER:$RABBITMQ_PASSWORD" \
  http://localhost:15672/api/queues/aegis/aegis.deadletter | python3 -c \
  'import sys,json;print("deadletter:",json.load(sys.stdin).get("messages"))'
```

> **Operational note:** changing a queue's arguments (e.g. TTL) requires deleting +
> recreating the queue **and restarting the middleware**, or the consumer stays bound
> to the old queue and stops consuming.
