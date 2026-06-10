# Load Test — Scénario d'attaque Juice Shop / Kali (ADR 002)

## Objectif

Ce runbook décrit un scénario d'attaque reproductible contre Juice Shop, exécuté
manuellement depuis Kali, pour produire les mesures attendues par
[ADR 002](../adr/002-mttt-measurement-protocol.md) : MTTT (p50/p95), durée de
l'étape LLM, et profondeur des files `aegis.triage` / `aegis.reports`, à comparer
avant/après l'architecture Ollama partitionnée.

Le scénario comporte deux phases :

1. **Bruit** — reconnaissance/scans automatisés générant un volume d'alertes de
   triage (et probablement plusieurs escalades LLM, qui remplissent
   `aegis.reports`).
2. **Exploit haute sévérité** — une injection SQL ciblée (rule 31112, level 10),
   garantie d'escalader vers `analyze_log()` quel que soit l'état de
   `aegis.reports`, pour vérifier que le triage d'un nouvel incident reste rapide
   pendant que le LLM est occupé sur le backlog de la phase 1.

## Prérequis

- Partie D de `poc-linux-startup.md` complétée : Juice Shop + nginx démarrés
  (`make docker-juiceshop-up`, port 9080), agent Wazuh `node1-host` configuré
  pour lire `docker/node1/juice-shop/logs/access.log` (D.2/D.3), et vérifié dans
  le Wazuh Dashboard (D.4).
- `NODE1_IP` récupéré (Partie E.1).
- Grafana ouvert sur le dashboard "AEGIS Crisis Dashboard"
  (`http://localhost:3000`) — panneaux à surveiller : "MTTT — Triage Duration
  p50/p95", "SLM Triage Duration p95", "LLM Analysis Duration p95", "Queue
  Depth — aegis.triage / aegis.reports".
- Prometheus accessible sur `http://localhost:9090` pour les requêtes PromQL
  d'ADR 002.

## Limite de collecte connue : seules les attaques visibles dans l'URL sont détectées

`nginx.conf` logue au format `combined` :
`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"` — c'est-à-dire IP
source, méthode + chemin + querystring, code de retour, taille, referer et
user-agent. **Le corps des requêtes POST et les en-têtes personnalisés
(`Authorization`, cookies) ne sont PAS logués**, donc invisibles pour les règles
Wazuh 31100+ qui parsent `data.url`/`data.request`.

Conséquence pour ce scénario :

- ✅ Détecté de façon fiable : scans (Nikto), injection SQL via paramètre GET
  (`?q=...`), brute-force HTTP (formulaire en POST, mais Wazuh détecte la
  *fréquence* des requêtes vers `/rest/user/login`, pas leur contenu),
  énumération de chemins.
- ❌ Non détecté par cette configuration : exploitation de l'API admin via JWT
  forgé (`Authorization: Bearer ...`) ou via mass assignment dans un corps JSON
  POST (ex. `{"role":"admin"}` sur `/api/Users`) — ces requêtes n'apparaissent
  dans aucun champ logué par `combined`.

→ Le scénario ci-dessous se limite donc volontairement aux attaques visibles
dans la ligne de requête (méthode + chemin + querystring), pour une détection
Wazuh fiable et reproductible. L'exploitation JWT/admin-API reste un point
aveugle de cette configuration de collecte — à traiter séparément si besoin
(logging du corps des requêtes via un module nginx dédié, hors scope ici).

## Phase 1 — Bruit (reconnaissance)

Lancer depuis Kali, contre `http://NODE1_IP:9080` :

```bash
# 1. Scan de vulnérabilités web — déclenche rule 31108 (scanner, level 10),
#    potentiellement plusieurs dizaines d'alertes
nikto -h http://NODE1_IP:9080 -o nikto_output.txt

# 2. Énumération de répertoires — chemins inconnus → 404 ; certains motifs
#    (../, /admin, /.git, etc.) peuvent matcher les règles "scanner"/"attack"
gobuster dir -u http://NODE1_IP:9080 -w /usr/share/wordlists/dirb/common.txt -t 20

# 3. Brute-force du formulaire de login (rule 31151, level 10) — Wazuh détecte
#    la fréquence des POST vers /rest/user/login, pas le contenu
hydra -l admin@juice-sh.op -P /usr/share/wordlists/rockyou.txt \
  NODE1_IP -s 9080 http-post-form \
  "/rest/user/login:email=^USER^&password=^PASS^:Invalid email or password"
```

> **Dimensionnement** : toute alerte de level ≥10 venant d'une IP inconnue
> (Kali, criticité `tier2` par défaut côté ChromaDB) **bypass la porte UEBA**
> (`rule_level <= 8` devient faux) — si le SLM la juge `is_suspect=true`, elle
> escalade vers `analyze_log()` (~5-10 min de LLM chacune sur le Pi). Un scan
> Nikto complet peut générer des dizaines d'alertes level 10, soit
> potentiellement plusieurs heures de backlog `aegis.reports`. Pour un test de
> 30-60 min, limiter Nikto à `-Tuning 9b` (XSS/SQLi seulement) ou ZAP à `-m 5`
> (5 min), et garder gobuster sur une wordlist courte (`common.txt`).

(Optionnel) Scan ZAP baseline, borné dans le temps :

```bash
zap-baseline.py -t http://NODE1_IP:9080 -m 5
```

## Phase 2 — Exploit haute sévérité (à mi-parcours)

Pendant que la phase 1 tourne encore (ou juste après), lancer l'injection SQL :

```bash
sqlmap -u "http://NODE1_IP:9080/rest/products/search?q=test" \
  --batch --level=3 --risk=2
```

**Comportement attendu** (rule 31112, level 10) :

1. `rule_level (10) > 8` → bypass systématique de la porte UEBA, quelle que soit
   la criticité de l'asset source.
2. SLM (`qwen25-aegis`) classe l'alerte `is_suspect=true` avec
   `confidence ≥ 0.5` → passe la porte de suspicion → `triage_escalated`.
3. `analyze_log()` envoie le contexte à Mistral (`mistral-aegis`, ~5-10 min) →
   `attack_confirmed=true`, `severity` probablement `critical` ou `high`
   (formule `risk_scorer` : `rule_level/15×0.20 = 0.133`, plus 0.30×SLM +
   0.50×LLM — un SLM/LLM confiants à ~0.8-0.9 donnent un `danger_score` proche
   de 0.8-1.0).
4. `AegisReport` envoyé à Shuffle (`http://localhost:3001` → workflow "AEGIS
   Alerts" → onglet Executions) — chercher l'exécution dont le résumé mentionne
   "SQL" / `/rest/products/search`.

## Pendant l'attaque — quoi observer

- **Grafana — "MTTT — Triage Duration p50/p95"** : doit rester dans la
  fourchette de référence (~8-18 s, voir `docs/raspberrypi-ollama-setup.md`)
  **pendant toute l'attaque**, y compris lorsque le panneau "LLM Analysis
  Duration p95" affiche des barres de plusieurs minutes.
- **Grafana — "Queue Depth — aegis.triage / aegis.reports"** : `aegis.triage`
  doit rester proche de 0 (le triage absorbe le flux au fil de l'eau) ;
  `aegis.reports` doit croître pendant la phase 1 puis se vider
  progressivement (1 rapport toutes les ~5-10 min).
- **RabbitMQ management** (`http://localhost:15672` → Queues) — vue
  alternative/complémentaire des mêmes files.
- **Logs middleware** :

  ```bash
  docker compose -f docker/node1/docker-compose.yml --env-file .env \
    logs -f middleware | grep -v posthog
  ```

  Chercher `triage_escalated` pour l'alerte `/rest/products/search` (phase 2),
  puis `report_constructed`/`pipeline_complete` quelques minutes plus tard.

## Mesures à consigner pour ADR 002

Relever, sur la fenêtre couvrant la phase 2 (du début de la phase 1 jusqu'à la
fin du backlog `aegis.reports`) :

```promql
# MTTT p50 / p95 sur la fenêtre d'attaque
histogram_quantile(0.50, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="triage"}[5m])) by (le))
histogram_quantile(0.95, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="triage"}[5m])) by (le))

# Durée LLM p95
histogram_quantile(0.95, sum(rate(aegis_pipeline_duration_seconds_bucket{stage="llm"}[5m])) by (le))

# Pic de profondeur des files sur la fenêtre d'attaque (ex. 1h)
max_over_time(rabbitmq_queue_messages{queue="aegis.triage", vhost="aegis"}[1h])
max_over_time(rabbitmq_queue_messages{queue="aegis.reports", vhost="aegis"}[1h])
```

Reporter les 4 valeurs dans le tableau "Results" d'
[ADR 002](../adr/002-mttt-measurement-protocol.md), sur la ligne "Before"
(architecture pré-`b9cf8ad`, sémaphore partagé, un seul `ollama serve`) ou
"After" (architecture actuelle, `ollama-slm`/`ollama-llm` partitionnés sur le
Pi) selon la configuration testée.

## Comparaison avant/après

- **After** (par défaut, code actuel) : exécuter le scénario tel quel, avec
  `ollama-slm`/`ollama-llm` configurés selon
  `docs/raspberrypi-ollama-setup.md`.
- **Before** : `git checkout` du commit précédant `b9cf8ad` pour le middleware,
  et pointer `OLLAMA_SLM_BASE_URL`/`OLLAMA_LLM_BASE_URL` vers une seule instance
  `ollama serve` (sémaphore partagé restauré par le checkout). Rejouer le
  scénario à l'identique.

## Nettoyage entre deux runs

```bash
# Vider les files avant un nouveau run pour repartir d'un état propre :
# RabbitMQ management (http://localhost:15672) → Queues → aegis.triage /
# aegis.reports → Purge Messages

make docker-juiceshop-down   # si Juice Shop n'est plus nécessaire
```
