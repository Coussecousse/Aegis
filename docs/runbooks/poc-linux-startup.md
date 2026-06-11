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

### 3. Wazuh certs permissions (Linux)

The `wazuh.indexer` container runs as UID 1000. If `docker/node1/wazuh/certs/` is
owned by your host user with mode `700` (common after `git clone` or volume restore
on Linux), the indexer fails at boot with `AccessDeniedException: .../certs` and
the manager/dashboard stay stuck in `Created`. Fix before first startup:

```bash
chmod 755 docker/node1/wazuh/certs
chmod 644 docker/node1/wazuh/certs/*.pem docker/node1/wazuh/certs/*.key
```

### 4. Environment file

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

### 5. POC LDAP variables in `.env`

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

The Pi runs two partitioned Ollama instances, reachable on WireGuard IP `10.0.0.1`:
SLM on `0.0.0.0:11434` (1 core) and LLM on `0.0.0.0:11435` (3 cores) — see
`docs/raspberrypi-ollama-setup.md` for the full architecture.

```bash
# curl is not installed in the middleware image — use Python instead
docker exec aegis-node1-middleware-1 python3 -c "
import urllib.request, json
for port, expected in [(11434, 'qwen25-aegis'), (11435, 'mistral-aegis')]:
    r = urllib.request.urlopen(f'http://10.0.0.1:{port}/api/tags', timeout=5)
    names = [m['name'] for m in json.loads(r.read()).get('models', [])]
    print(port, names)
"
# Expected: qwen25-aegis listed for :11434, mistral-aegis listed for :11435
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
scp docs/modelfiles/Modelfile.slm-qwen25  PI_USER@PI_IP:~/
scp docs/modelfiles/Modelfile.llm-mistral PI_USER@PI_IP:~/

# SSH into the Pi
ssh PI_USER@PI_IP

# Check base models are present
ollama list
# Required: qwen2.5:1.5b, mistral:7b-instruct-q4_K_M
```

**Replace the single `ollama.service` with two CPU-pinned instances** — SLM on
:11434 (1 core) and LLM on :11435 (3 cores), required for Node1 to reach both via
WireGuard. Full rationale and verification steps in
`docs/raspberrypi-ollama-setup.md`; condensed here for the POC:

```bash
# Stop and disable the default single-instance service (frees port 11434)
sudo systemctl disable --now ollama

# SLM instance — 1 core, port 11434
sudo tee /etc/systemd/system/ollama-slm.service > /dev/null << 'EOF'
[Unit]
Description=Ollama SLM instance (triage, Qwen 2.5 1.5B)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
Environment="OLLAMA_HOST=0.0.0.0:11434"
User=ollama
Group=ollama
Restart=always
RestartSec=3
AllowedCPUs=0

[Install]
WantedBy=multi-user.target
EOF

# LLM instance — 3 cores, port 11435
sudo tee /etc/systemd/system/ollama-llm.service > /dev/null << 'EOF'
[Unit]
Description=Ollama LLM instance (analysis, Mistral 7B Q4)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
Environment="OLLAMA_HOST=0.0.0.0:11435"
User=ollama
Group=ollama
Restart=always
RestartSec=3
AllowedCPUs=1-3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ollama-slm ollama-llm

# Verify — must show *:11434 and *:11435 (all interfaces)
ss -tlnp | grep -E '11434|11435'
```

```bash
# Create AEGIS-tuned model variants (either instance — shared model store)
ollama create qwen25-aegis  -f ~/Modelfile.slm-qwen25
ollama create mistral-aegis -f ~/Modelfile.llm-mistral

# Verify (from the Pi)
ollama list
# Must include: qwen25-aegis, mistral-aegis
```

**Verify from Node1 host** (curl is not installed in the middleware container):

```bash
python3 -c "
import urllib.request, json
for port, expected in [(11434, 'qwen25-aegis'), (11435, 'mistral-aegis')]:
    r = urllib.request.urlopen(f'http://PI_IP:{port}/api/tags', timeout=5)
    print(port, [m['name'] for m in json.loads(r.read()).get('models', [])])
"
# Must list qwen25-aegis on :11434 and mistral-aegis on :11435
```

> **Air-gapped Pi note**: `ollama create <name> -f Modelfile` with a `FROM <model>`
> directive triggers a manifest check against `registry.ollama.ai`, even if the base
> model is already present locally — this fails with no DNS/internet. Either pull the
> base model once with internet temporarily enabled (`echo "nameserver 8.8.8.8" | sudo
> tee /etc/resolv.conf`, `ollama pull qwen2.5:1.5b`, then restore the normal
> `/etc/resolv.conf` and disable internet again), or point `FROM` at the local digest
> via `ollama show qwen2.5:1.5b --modelfile | grep "^FROM"`.

### C.2 — Exposer les métriques hardware (node_exporter, done once)

`prometheus-node-exporter` expose CPU, RAM, température et d'autres métriques système
sur le port 9100, que Prometheus (Node1) scrape toutes les 30 s via WireGuard.

**Prérequis** : connexion internet active sur le Pi (désactiver temporairement tout
blocage réseau si nécessaire, puis le rétablir après l'install).

```bash
# SSH into the Pi — installer le package Debian (auto-start systemd)
sudo apt update && sudo apt install -y prometheus-node-exporter

# Vérifier que le service est actif et écoute sur le port 9100
sudo systemctl status prometheus-node-exporter
ss -tlnp | grep 9100

# Sanity check : les trois métriques clés utilisées par le dashboard AEGIS
curl -s http://localhost:9100/metrics | grep -E \
  "^node_thermal_zone_temp|^node_memory_MemAvailable_bytes|^node_cpu_seconds_total"
```

**Firewall** : si nftables est actif avec une règle `iifname "wg0" accept` dans la chain
`input`, le port 9100 est déjà accessible depuis Node1 (10.0.0.2) via WireGuard — aucune
règle supplémentaire n'est nécessaire.

> **Note température** : `node_thermal_zone_temp{type="cpu-thermal",zone="0"}` renvoie
> directement des **degrés Celsius** (ex. `50.7`) — node_exporter fait lui-même la
> conversion depuis les millidegrés du noyau. Les queries Grafana n'ont **pas** à diviser
> par 1000.

---

## Partie D — Juice Shop (cible d'attaque réaliste)

OWASP Juice Shop est une application web volontairement vulnérable. Elle sert de cible aux attaques
Kali, dont les requêtes sont interceptées par nginx, loguées en format Apache, puis analysées par
le Wazuh agent (règles 31100+).

### D.1 — Lancer Juice Shop + nginx

```bash
make docker-juiceshop-up
# Vérifier
curl -s -o /dev/null -w "%{http_code}" http://localhost:9080   # 200
```

Juice Shop est accessible sur le port **9080**. nginx reverse-proxifie vers Juice Shop et écrit ses
access logs dans `docker/node1/juice-shop/logs/access.log` (monté sur le host pour le Wazuh agent).

### D.2 — Installer le Wazuh agent sur Node1 (Ubuntu 24.04, done once)

```bash
# Télécharger le paquet
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb

# Installer avec le manager Docker (127.0.0.1 = manager exposé sur le host)
sudo WAZUH_MANAGER='127.0.0.1' WAZUH_AGENT_NAME='node1-host' \
  dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb

# Démarrer l'agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Vérifier
sudo systemctl status wazuh-agent | grep Active
```

> **Port 1515 requis** : le manager doit exposer le port 1515 (enregistrement agent).
> C'est déjà configuré dans `docker-compose.yml`.

Si l'agent ne se connecte pas automatiquement, forcer l'enregistrement :

```bash
sudo /var/ossec/bin/agent-auth -m 127.0.0.1 -p 1515 -A node1-host
sudo systemctl restart wazuh-agent
```

Vérifier la connexion via l'API manager :

```bash
TOKEN=$(curl -su "wazuh-wui:WAZUH_API_PASSWORD" \
  "https://localhost:55000/security/user/authenticate?raw=true" -k)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents" | python3 -c "
import sys,json
for a in json.load(sys.stdin)['data']['affected_items']:
    print(a['id'], a['name'], a['status'])
"
# Doit afficher : 001 node1-host active
```

### D.3 — Configurer l'agent pour surveiller les logs nginx

Ajouter la source de log à la configuration de l'agent :

```bash
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null << 'EOF'
<ossec_config>
  <localfile>
    <log_format>apache</log_format>
    <location>/CHEMIN_ABSOLU_VERS_REPO/docker/node1/juice-shop/logs/access.log</location>
  </localfile>
</ossec_config>
EOF

sudo systemctl restart wazuh-agent
```

Remplacer `CHEMIN_ABSOLU_VERS_REPO` par le chemin réel vers le dépôt (ex. `/home/user/src/aegis`).

### D.4 — Vérifier dans le Wazuh Dashboard

1. Ouvrir `https://localhost:5601`
2. **Agents** → `node1-host` doit apparaître en vert (`Active`)
3. Faire une requête test : `curl http://localhost:9080`
4. Dans **Security events** → les logs nginx doivent apparaître

---

## Partie E — Attaques Kali (simulation réaliste)

Depuis la machine Kali sur le même réseau, cibler `http://NODE1_IP:9080` (Juice Shop via nginx).

> Pour le scénario complet de mesure MTTT (bruit + exploit haute sévérité,
> ADR 002), voir
> [load-test-juiceshop-kali.md](load-test-juiceshop-kali.md).

### E.1 — Récupérer l'IP de Node1

```bash
# Sur Node1
ip addr | grep "inet " | grep -v 127 | awk '{print $2}'
```

### E.2 — Attaques et règles Wazuh attendues

| Attaque | Outil Kali | Règle Wazuh | Level |
|---|---|---|---|
| Scan de vulnérabilités web | `nikto -h http://NODE1_IP:9080` | 31108 (scanner) | 10 |
| SQL injection | `sqlmap -u "http://NODE1_IP:9080/rest/products/search?q=1"` | 31112 | 10 |
| Brute force login | `hydra -l admin@juice-sh.op -P rockyou.txt NODE1_IP http-post-form "..."` | 31151 | 10 |
| Directory traversal | `curl "http://NODE1_IP:9080/../etc/passwd"` | 31120 | 10 |
| Scan de ports | `nmap -sS -O NODE1_IP` | 40101 | 8 |
| SSH brute force | `hydra -l root -P rockyou.txt ssh://NODE1_IP` | 5712 | 10 |

### E.3 — Commandes Kali rapides

```bash
# Scan complet Nikto (déclenche plusieurs règles Wazuh)
nikto -h http://NODE1_IP:9080 -o nikto_output.txt

# SQL injection automatique
sqlmap -u "http://NODE1_IP:9080/rest/products/search?q=test" \
  --batch --level=3 --risk=2

# Scan nmap agressif (déclenche règles HIDS)
nmap -sV -O --script=vuln NODE1_IP
```

### E.4 — Observer AEGIS réagir

```bash
# Logs middleware en direct
docker compose -f docker/node1/docker-compose.yml --env-file .env \
  logs -f middleware | grep -v posthog

# Vérifier la file RabbitMQ (alertes en attente de traitement)
# http://localhost:15672 → Queues → aegis.triage
```

Les rapports AEGIS apparaissent dans **Shuffle** (`http://localhost:3001`) →
onglet **Executions** du workflow "AEGIS Alerts".

---

## Partie F — Shuffle SOAR (human-in-the-loop)

### F.1 — Démarrer Shuffle

```bash
docker compose -f docker/node1/docker-compose.yml --env-file .env \
  --profile full up -d shuffle-database shuffle-backend shuffle-orborus shuffle-frontend
```

Attendre ~2 min. Vérifier : `http://localhost:3001`

> **Le volume `shuffle-apps` ne survit pas à un `down -v` ou un prune agressif.**
> S'il est vide (`docker exec aegis-node1-shuffle-backend-1 ls /shuffle-apps` ne renvoie rien),
> l'UI affiche "Couldn't find the app you're looking for" pour `Shuffle Tools` et les autres
> apps. Recharger les apps avant de configurer un workflow :
>
> ```bash
> docker exec aegis-node1-shuffle-backend-1 sh -c "
>   cd /tmp && wget -q https://github.com/Shuffle/shuffle-apps/archive/refs/heads/master.tar.gz -O apps.tar.gz &&
>   tar xzf apps.tar.gz && cp -r python-apps-master/* /shuffle-apps/ &&
>   rm -rf apps.tar.gz python-apps-master"
> docker restart aegis-node1-shuffle-backend-1
> ```
>
> Idem pour les **workflows** : ils sont stockés dans `shuffle-database` (OpenSearch) et
> disparaissent au même titre. Pour ne plus jamais reconfigurer "AEGIS Alerts" à la main :
> exporter le workflow depuis l'UI (bouton **Export** dans l'éditeur → JSON au schéma Shuffle
> réel) et le réimporter via **Import** au prochain démarrage.

> **Docker Engine ≥ 29 (API ≥ 1.44)** : le client Docker embarqué dans Shuffle 1.2.0
> négocie en API 1.41 et se fait rejeter par le démon (`client version 1.41 is too old.
> Minimum supported API version is 1.44`). Sans ce correctif, le backend ne peut pas
> builder les apps ni gérer les conteneurs d'exécution. Le compose force déjà
> `DOCKER_API_VERSION: "1.44"` sur `shuffle-backend` et `shuffle-orborus` — vérifier que
> ces variables sont bien présentes si tu modifies le fichier.

### F.2 — Première configuration (done once)

1. Créer un compte admin sur `http://localhost:3001`
2. **Apps** → chercher `Shuffle Tools` → l'activer si absent
3. **New Workflow** → nommer `AEGIS Alerts`
4. Glisser **Shuffle Tools** sur le canvas, puis ajouter un trigger **Webhook**
   (via la barre de recherche du canvas — l'option "Starting node" et la section
   "Triggers" séparée n'existent pas dans cette version de l'UI ; le nœud sans
   connexion entrante sert de point de départ)
5. **Save** → activer le workflow (toggle en haut)
6. Cliquer sur le nœud Webhook → copier l'**ID du hook** dans l'URL affichée

> **Important** : l'UI affiche l'URL externe `http://localhost:3001/api/v1/hooks/webhook_XXXX`
> (via le frontend, port 3001). Le middleware AEGIS tourne dans le réseau Docker interne
> et doit appeler le **backend** directement — reconstruire l'URL avec le même ID de hook :
> `http://shuffle-backend:5001/api/v1/hooks/webhook_XXXX`

### F.3 — Récupérer les identifiants Orborus

Après le premier démarrage, récupérer l'ORG_ID et l'API key pour Orborus :

```bash
# ORG_ID (dans les logs du backend)
docker logs aegis-node1-shuffle-backend-1 2>&1 | \
  grep "organization" | tail -1 | grep -oE '[0-9a-f-]{36}'

# API key : Shuffle UI → icône profil (haut droite) → copier la clé
```

Mettre à jour `.env` :

```bash
# Remplacer les valeurs CHANGE_ME
sed -i 's/SHUFFLE_ORG_ID=.*/SHUFFLE_ORG_ID=VOTRE_ORG_ID/' .env
sed -i 's/SHUFFLE_API_KEY=.*/SHUFFLE_API_KEY=VOTRE_API_KEY/' .env
sed -i 's|SHUFFLE_WEBHOOK_URL=.*|SHUFFLE_WEBHOOK_URL=http://shuffle-backend:5001/api/v1/hooks/VOTRE_HOOK_ID|' .env

# Redémarrer le middleware avec le nouveau webhook
docker compose -f docker/node1/docker-compose.yml --env-file .env \
  up -d --no-build middleware
```

### F.4 — Vérifier la réception des alertes

Envoyer une alerte test :

```bash
python3 - <<'EOF'
import urllib.request, json, base64, uuid
RABBIT_URL = "http://localhost:15672/api/exchanges/aegis/aegis.alerts/publish"
auth = base64.b64encode(b"aegis:RABBITMQ_PASSWORD").decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}
alert = {
    "id": str(uuid.uuid4()), "timestamp": "2026-01-01T00:00:00Z",
    "rule_id": 5712, "rule_level": 12,
    "rule_description": "SSH brute force test",
    "source_agent": "DC-01", "source_ip": "DC-01",
    "full_log": "Test: Failed password for root from 10.0.0.1 port 22 ssh2 (x30)",
    "decoder_name": "sshd",
}
payload = {"properties": {}, "routing_key": "alert.raw",
           "payload": json.dumps(alert), "payload_encoding": "string"}
req = urllib.request.Request(RABBIT_URL, json.dumps(payload).encode(), headers, method="POST")
print(json.loads(urllib.request.urlopen(req, timeout=5).read()))
EOF
```

Après ~5 min (traitement Pi), l'exécution apparaît dans Shuffle avec le rapport complet :
`attack_type`, `severity`, `summary`, `recommended_action`, `requires_human_validation`.

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
| Shuffle SOAR | http://localhost:3001 | compte créé au premier lancement |
| Juice Shop | http://localhost:9080 | — (cible d'attaque, pas de credentials) |

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

### SLM/LLM timeouts on Raspberry Pi (CPU-only inference)

**Cause**: the Pi runs Ollama in pure CPU inference (`/api/ps` reports `size_vram: 0` for
both models — no GPU offload). Measured throughput on a minimal prompt was **~2 sec/token**
(12.8 s for 6 tokens, with the model already resident — `load_duration` near 0). At that rate
a full triage response easily exceeds a 10–30 s timeout.

**Fix** — two changes work together (already applied in the codebase + `.env`):

1. **Cap SLM output length** so generation time stays bounded — the SLM only needs a small
   JSON (`is_suspect`/`confidence`/`behavior_category`/`reasoning_short`/`raw_probabilities`):
   `ollama_client.generate(..., num_predict=180)` in [pipeline.py](../../src/aegis/middleware/pipeline.py).
2. **Realistic timeouts** matching measured throughput — set in root `.env`:

```
SLM_TIMEOUT=90
LLM_TIMEOUT=600
```

Even 90 s for triage is still far faster than a manual analyst review (the actual MTTT
baseline this POC compares against), so it does not compromise the "fast alerting" goal —
it just stops fighting the Pi's real CPU-only throughput. If the LLM still times out, the
pipeline gracefully falls back to SLM-based risk scoring and the alert still reaches Shuffle
(see `llm_error` → `fallback: using_slm_confidence` in middleware logs).

Both models now run with `keep_alive=-1` (kept resident in RAM indefinitely) — see
"SLM model swap: TinyLlama → Qwen 2.5 1.5B" below for why this is safe on a 16 GB Pi.

Then rebuild and restart middleware:

```bash
make docker-build && docker system prune -f
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d --no-build middleware
```

### Consumer crashes with "Unable to nack all messages (N sub-exceptions)"

**Cause**: a Kali scan burst queued ~900 alerts (mostly Auditd "promiscuous mode" events —
a side effect of network scanning tools) at once. Without `prefetch_count`, RabbitMQ pushed
the entire backlog onto the consumer's channel. With each pipeline run taking minutes
(LLM-bound — see above), the channel held hundreds of unacked messages and the broker
closed it (`ChannelInvalidStateError`); the consumer then crashed trying to nack the whole
backlog at once.

**Fix**: `channel.set_qos(prefetch_count=1)` in [consumer.py](../../src/aegis/middleware/consumer.py)
`connect()` — RabbitMQ now holds the backlog server-side (where it's safe) and delivers one
message at a time, exactly the throttling the architecture relies on to keep the SLM/LLM
from being flooded. `connect_robust` already auto-reconnects, so the system self-heals even
if a burst occurs before the rebuild.

### Decoupled two-stage pipeline (triage / analysis)

**Why**: even with `prefetch_count=1`, a single consumer running the whole pipeline
sequentially (SLM → RAG → LLM → scoring → report → Shuffle) means the fast SLM triage
(~16 s after the `num_predict`/`keep_alive` fixes above) sits idle while the LLM spends
4–6 minutes generating a report for the *previous* alert. During a Kali burst (~900
messages) this serialization — not SLM throughput — was the real bottleneck.

**Fix**: the pipeline is now split into two independently running consumers connected
through RabbitMQ:

- **Triage consumer** (`RabbitMQConsumer`, queue `aegis.triage`) runs
  `pipeline.triage_log()` — SLM call + suspicion gate, RAG fetch, UEBA false-positive
  gate. Alerts that pass are bundled into an `EscalatedAlert` (Pydantic model in
  [models.py](../../src/aegis/middleware/models.py)) and published to the `aegis.alerts`
  exchange with routing key `alert.escalated`, bound to the `aegis.reports` queue
  (binding declared in
  [definitions.json](../../docker/node1/rabbitmq/config/definitions.json)).
- **Analysis consumer** (`RabbitMQAnalysisConsumer`, queue `aegis.reports`, in
  [consumer_analysis.py](../../src/aegis/middleware/consumer_analysis.py)) runs
  `pipeline.analyze_log()` — LLM call (with SLM-confidence fallback on timeout), risk
  scoring, `AegisReport` construction, and the Shuffle SOAR webhook. It does not need a
  ChromaDB client: the RAG context already travels inside the `EscalatedAlert` bundle.

Both consumers run concurrently via `asyncio.gather()` in
[`__main__.py`](../../src/aegis/__main__.py), alongside the identity-sync consumer.
They share a single `MetricsCollector` instance, since Prometheus' global registry
rejects duplicate metric registrations. There is no Ollama-call serialization at the
Python level (see "Triage/analysis serialization" below for how concurrency is now
handled).

New env var: `RABBITMQ_REPORTS_QUEUE` (default `aegis.reports`, mirrors
`RABBITMQ_QUEUE`/`RABBITMQ_IDENTITY_QUEUE` — see `.env.example`).

**To verify the decoupling end-to-end**: run a Kali burst against Juice Shop and watch
the middleware logs — you should see the triage consumer emitting `slm_complete` /
`alert_escalated` for new alerts *while* the analysis consumer is still mid-`llm_start`
on an earlier one, and the `aegis.reports` queue filling/draining in the RabbitMQ
management UI (http://localhost:15672 → Queues).

### SLM model swap: TinyLlama → Qwen 2.5 1.5B

**Cause**: TinyLlama 1.1B always returned the same `confidence: 0.88` /
`behavior_category: lateral_movement` regardless of the alert content — a 1.1B model is
too small to reason from data and instead copies the example values baked into
`Modelfile.slm-tinyllama` verbatim.

**Fix**: switched the SLM to **Qwen 2.5 1.5B** (Apache 2.0) — still small enough for
CPU-only inference on the Pi (~1 GB RAM, ~8-18 s per triage when idle) but noticeably
better at following a JSON schema and reasoning over the actual alert fields. New
Modelfile: [Modelfile.slm-qwen25](../modelfiles/Modelfile.slm-qwen25).

- `SLM_MODEL`/`LLM_MODEL` are now read from the environment in
  [pipeline.py](../../src/aegis/middleware/pipeline.py) (`_SLM_MODEL`/`_LLM_MODEL`
  module constants, defaulting to `qwen25-aegis`/`mistral-aegis`) — switching models no
  longer requires a code change, only `.env` + `ollama create`.
- Both models now run with `keep_alive=-1`. The Pi has 16 GB RAM; Qwen 2.5 1.5B (~1 GB)
  and Mistral 7B Q4 (~4.5 GB) fit simultaneously with no swap, so there's no need to
  unload the LLM between reports.

### MTTT metric (`stage="triage"`) and RabbitMQ queue-depth panels

**What changed**: `triage_log()` now calls `MetricsCollector.record_triage()` on every
exit path (suspicion-gate discard, RAG error, UEBA-gate discard, escalation), exposed as
`aegis_pipeline_duration_seconds_bucket{stage="triage"}` — the MTTT (Mean Time To Triage)
signal used by [ADR 002](../adr/002-mttt-measurement-protocol.md). The Crisis dashboard
gained two panels: "MTTT — Triage Duration p50/p95" and "Queue Depth — aegis.triage /
aegis.reports".

**Operational step required**: the queue-depth panel needs
`prometheus.return_per_object_metrics = true`
([rabbitmq.conf](../../docker/node1/rabbitmq/config/rabbitmq.conf)), which RabbitMQ only
reads at startup. Restart the container after pulling this change:

```bash
docker compose -f docker/node1/docker-compose.yml --env-file .env restart rabbitmq
```

Verify with:

```bash
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=rabbitmq_queue_messages{queue="aegis.triage"}'
```

The middleware/collector images still need the usual rebuild for the `record_triage()`
code change (Step 1).

**Qwen echo bug**: with the old prompt format (`Rule: ... | Level: ...`), Qwen 2.5
echoed the input alert back as JSON (`{"rule_id": ..., "rule_level": ...}`) instead of
producing the triage schema — `format: "json"` in Ollama's `/api/generate` only enforces
*valid JSON*, not a specific schema, so a small model can "satisfy" it by reformatting
the input. Fixed by:
- rewriting `Modelfile.slm-qwen25`'s `SYSTEM` directives onto single lines (multi-line
  `SYSTEM { ... }` blocks are unreliable), and
- rewriting `build_slm_prompt()` in
  [prompt_builder.py](../../src/aegis/middleware/prompt_builder.py) with explicit
  `ALERT DATA: ...` / `OUTPUT: JSON triage with fields ...` framing, so the model can no
  longer mistake "the data" for "the requested output".

**`OLLAMA_NUM_PARALLEL`**: tested `OLLAMA_NUM_PARALLEL=2` (to let SLM and LLM run
concurrently) after removing the semaphore, but on the Pi's 4 ARM cores both inferences
slowed down/timed out simultaneously — worse than serial. Reverted to
`OLLAMA_NUM_PARALLEL=1` (Ollama's default internal queue serializes requests; each one
still runs at full speed once it's its turn).

### Triage/analysis serialization: dedicated SLM/LLM Ollama instances

**Cause**: even with the Python-level semaphore removed, both consumers still pointed
at the *same* Ollama instance on `:11434`. SLM triage and LLM analysis requests landed
in that single instance's internal queue (`OLLAMA_NUM_PARALLEL=1`), so a 5-10 min LLM
analysis still queued behind every triage call (and vice versa) — the `aegis.triage`
queue backed up and MTTT spiked for every alert pending during an analysis.

**Fix**: the Pi now runs two independent `ollama serve` processes, each pinned to its
own CPU cores via systemd `AllowedCPUs` — `ollama-slm` (1 core, port 11434,
`qwen25-aegis`) and `ollama-llm` (3 cores, port 11435, `mistral-aegis`). The triage
consumer's `OllamaClient` points at `OLLAMA_SLM_BASE_URL`, the analysis consumer's at
`OLLAMA_LLM_BASE_URL` (see `.env.example`) — there is no shared instance and no shared
lock between them. Full systemd unit definitions and verification steps:
[raspberrypi-ollama-setup.md](../raspberrypi-ollama-setup.md).

### CPU oversubscription within each Ollama instance (`num_thread` mismatch)

**Cause**: `AllowedCPUs` confines each `ollama serve` process to a cgroup cpuset, but
`llama.cpp` does not read the cpuset — it defaults its thread pool to the *host's* total
core count (4 on the Pi 5). With `ollama-slm` confined to 1 core (`AllowedCPUs=0`) but
spawning 4 worker threads, the threads thrash on barrier spinlocks waiting for siblings
the scheduler never runs concurrently — turning a sub-second SLM call into 10+ minutes
(observed: `SLM_TIMEOUT=90` exceeded 3 times in a row). The same mismatch applies to
`ollama-llm` (3 cores, `AllowedCPUs=1-3`, but 4 threads by default).

**Fix**: set `PARAMETER num_thread <N>` in each Modelfile to match its instance's
`AllowedCPUs` core count — `num_thread 1` in
[Modelfile.slm-qwen25](../modelfiles/Modelfile.slm-qwen25) and `num_thread 3` in
[Modelfile.llm-mistral](../modelfiles/Modelfile.llm-mistral). `num_thread` is baked into
the model at build time, not read per-request — rebuild
(`ollama create <name> -f Modelfile...`) and restart the corresponding systemd unit after
any Modelfile change.

### False positive: "auditd: Device enables promiscuous mode" on the AEGIS host itself

**Cause**: the Wazuh agent on `node1-host` (the host running the AEGIS stack) reports
rule `80710` (level 10, "Device enables promiscuous mode") whenever `dockerd` creates a
container network and brings up a `veth...` interface in promiscuous mode. This is
normal Docker behaviour, not an attack — but the pipeline still escalated it and
generated a full `AegisReport`, because rule `80710` is a *legitimate* attack indicator
(network sniffing / lateral movement) when it fires on a monitored business asset.

**Why not filter by `rule_id`**: that would blind AEGIS to genuine sniffing attempts
everywhere just to silence noise from one host. See `_operational_rules` in
[wazuh_forwarder.py](../../src/aegis/collectors/wazuh_forwarder.py) — it exists only for
rules that are *intrinsically* operational (agent lifecycle events 501/502/503/510-513)
regardless of which host fires them. Rule `80710` is not one of those.

**Why not filter by agent name either** (an approach that shipped briefly and was
reverted): `node1-host` is not a dedicated AEGIS-infrastructure agent — in this POC's
topology it is the *only* Wazuh agent, and it monitors both the AEGIS host and the Juice
Shop attack target. Excluding it by name silently dropped every Kali attack detection
too (rules 31103/31153/31154/31533 all fire as `agent=node1-host`), causing a total
detection blackout during a live attack session. Agent-name filtering would only be
valid in a topology where the AEGIS host has its own dedicated agent, separate from the
agents monitoring the assets it defends — an assumption that does not hold here and must
be re-validated against the real deployed topology before ever being re-attempted.

**Fix**: filter on the *log content* instead — the only axis that actually distinguishes
"Docker's own veth churn" from "a real sniffing attempt", regardless of which agent or
host reports it. `WazuhAlertParser.parse_alert()` drops an alert when `rule_id == 80710`
**and** `full_log` contains the auditd `comm="dockerd"` signature:

```python
if rule_id == 80710 and 'comm="dockerd"' in full_log:
    return None
```

The same rule `80710` triggered by any *other* process (a real sniffing tool, a manual
`ip link set ... promisc on`, etc.) — on `node1-host` or any other agent — still reaches
the pipeline unaffected.

### Shuffle frontend affiche "Waiting for database" après un redémarrage de container

**Cause** : nginx dans `shuffle-frontend` résout le hostname `shuffle-backend` une seule
fois au démarrage. Si le backend a été recréé (nouvelle IP), nginx garde l'ancienne en
cache et renvoie 502, ce qui fait afficher "Waiting for the Shuffle database" dans l'UI.

**Fix** : recharger nginx sans redémarrer le container :

```bash
docker exec aegis-node1-shuffle-frontend-1 nginx -s reload
```

Vérifier ensuite que l'API répond : `curl -s http://localhost:3001/api/v1/docs | head -1`

### Shuffle `--force-recreate` prend toute la stack avec lui

**Cause** : `docker compose up --force-recreate shuffle-frontend` (sans `--no-deps`) force
Compose à stopper les dépendants du service en cascade — ce qui peut emporter toute la
stack principale (RabbitMQ, Wazuh, middleware…) avec lui.

**Règle** : pour les services Shuffle, toujours ajouter `--no-deps` :

```bash
docker compose -f docker/node1/docker-compose.yml --env-file .env --profile full \
  up -d --no-deps shuffle-database shuffle-backend shuffle-frontend shuffle-orborus
```

### Explosion de containers worker Shuffle au redémarrage

**Cause** : chaque alerte dans `aegis.triage` qui atteint Shuffle déclenche un workflow
qui spawne un container `worker-xxx`. Si la queue s'est accumulée pendant une session
d'attaque (ex. 37 alertes non traitées), redémarrer la stack fait partir tous les
workflows en parallèle — le Pi se sature, le SSH lâche, et des containers tombent en
cascade.

**Avant toute nouvelle session d'attaque**, vérifier la profondeur de la queue et purger
si nécessaire :

```bash
# Voir le nombre de messages en attente
docker exec aegis-node1-rabbitmq-1 rabbitmqctl list_queues -p aegis name messages

# Purger si la queue est trop remplie (via l'API HTTP — rabbitmqctl purge_queue
# a une syntaxe variable selon la version)
source .env
curl -s -u "${RABBITMQ_USER}:${RABBITMQ_PASSWORD}" \
  -X DELETE "http://localhost:15672/api/queues/aegis/aegis.triage/contents"

# Ou depuis le browser : localhost:15672 → Queues → aegis.triage → bouton Purge
```

Supprimer les worker containers stoppés après un épisode de saturation :

```bash
docker ps -a --filter "name=worker-" -q | xargs -r docker rm -f
```
