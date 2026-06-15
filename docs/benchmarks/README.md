# Banc de KPI / benchmarks AEGIS

Ce document explique **ce qu'on mesure sur AEGIS, pourquoi, comment c'est calculé,
et les objectifs à atteindre**. Objectif : savoir à quoi s'attendre (qualité des
rapports, temps de réponse, taux de faux positifs…) de façon reproductible.

---

## 1. Vocabulaire (à lire en premier)

- **Alerte** : un événement détecté par Wazuh (ex. « tentative d'injection SQL »).
- **Triage (étage rapide, modèle SLM)** : pour chaque alerte, un petit modèle décide
  vite s'il faut **jeter** (bruit) ou **approfondir**.
- **Escalade** : quand le triage décide d'approfondir une alerte.
- **Analyse (étage lent, modèle LLM)** : un gros modèle rédige le **rapport** détaillé
  (type d'attaque, résumé, action recommandée) — c'est lent (minutes) sur le Raspberry Pi.
- **Rapport** : le résultat final, validé ensuite par un humain.
- **p50 / p95** : façons de résumer des durées. p50 = la médiane (la moitié des alertes
  vont plus vite). p95 = le « presque pire cas » (95 % vont plus vite ; on ignore les 5 %
  extrêmes). On vise des objectifs sur le **p95** car c'est ce que vit l'utilisateur dans
  les mauvais moments.

---

## 2. Quels tests sont faits ?

Deux familles, lancées par deux commandes.

### Niveau 1 — tests automatiques rapides (`make benchmark-ci`)
Tournent sur un PC normal, **sans le Raspberry Pi**, en quelques secondes. On rejoue un
**corpus d'alertes étiquetées** (on connaît la bonne réponse à l'avance) en simulant les
modèles, pour vérifier le comportement **déterministe** :
- les rapports contiennent bien tous les champs et une **action concrète** (la vraie IP /
  le vrai endpoint) ;
- la **sévérité** attribuée est cohérente ;
- la **porte UEBA** (qui décide jeter/approfondir) prend les bonnes décisions ;
- le **taux de faux positifs** (voir §3) ;
- le **connecteur identité** (LDAP→base) marche, même quand le LDAP tombe.

### Niveau 2 — test réel sur la stack + le Pi (`make benchmark`)
Lance de **vraies attaques** (curl + outils Kali) contre la cible, puis mesure les
**temps réels** (triage, analyse LLM), le **débit**, et la qualité des rapports produits
par le vrai modèle. C'est là qu'on obtient les vrais temps de réponse.

---

## 3. Les KPI : définition, calcul, objectif

Pour chaque KPI : **ce que c'est → comment on le calcule → l'objectif (et pourquoi)**.

### Taux de faux positifs — ≤ 5 %
- **Définition** : un faux positif = une alerte qui **n'est pas une vraie attaque** mais
  qu'AEGIS approfondit quand même jusqu'à produire un rapport. Exemple concret : sur
  l'hôte qui héberge AEGIS, « netstat : un port a changé » (règle 533) est une activité
  **normale**, pas une attaque — si AEGIS en fait un rapport, c'est un faux positif.
- **Comment on le calcule** : on rejoue un lot d'alertes **bénignes connues** (étiquetées
  « pas une attaque » dans le corpus). Puis :

  `taux de FP = (alertes bénignes escaladées en rapport) ÷ (total des alertes bénignes)`

- **Objectif : ≤ 5 %.** Pourquoi : chaque faux positif consomme **un cycle LLM de 5-9 min**
  sur le Pi et noie le vrai signal. On en tolère un peu, pas beaucoup.
- **Mesuré aujourd'hui** : **0 %** quand le filtre de bruit est activé
  (`WAZUH_EXCLUDED_RULES=533`), **33 %** sans le filtre (l'alerte netstat passe). Ça
  chiffre l'utilité du filtre.

### Rappel d'attaque (ne rien rater) — ≥ 95 % (viser 100 %)
- **Définition** : la proportion de **vraies attaques** qui sont bien approfondies.
- **Calcul** : `(vraies attaques escaladées) ÷ (total des vraies attaques du corpus)`.
- **Objectif ≥ 95 %.** Pourquoi : rater une attaque est la pire défaillance pour un SOC.

### Temps de réponse — triage et analyse
- **MTTT (temps de triage), p95 < 90 s.** Temps que met l'étage rapide à décider
  jeter/approfondir. Calcul : on enregistre la durée de chaque triage, on lit le p95.
  Pourquoi 90 s : le triage doit rester quasi temps réel pour ne pas accumuler de retard.
- **Temps d'analyse LLM, p95 < 600 s (idéal < 420 s).** Temps pour rédiger un rapport.
  Lent car le Pi calcule sur CPU. Pourquoi 600 s : c'est le budget configuré
  (`LLM_TIMEOUT`) ; au-delà l'analyse est abandonnée.
- **Bout-en-bout (alerte → rapport), p95 < ~10 min.** Acceptable pour un rapport relu
  par un humain sur ce matériel.

### Débit sous charge (rafale d'attaques)
- **File de triage ≈ 0 pendant une rafale.** Calcul : pic du nombre de messages en attente
  dans `aegis.triage`. Pourquoi : prouve que le triage absorbe le flux sans accumuler.
- **Perte d'alertes = 0.** Calcul : alertes envoyées vs alertes effectivement traitées.
  Pourquoi : perdre une alerte sous charge est inacceptable pour un SOC.

### Qualité des rapports
- **Rapport en JSON valide = 100 %** : un rapport mal formé est inexploitable (il retombe
  sur une analyse dégradée). Calcul : rapports valides ÷ rapports produits.
- **Champs complets = 100 %** : les 10 champs attendus sont présents.
- **Action concrète = 100 % (sur règles connues)** : l'action recommandée cite la **vraie
  IP / le vrai endpoint** (ex. « Bloquer 172.20.0.1 au pare-feu ; auditer
  /rest/products/search »), pas un conseil générique.
- **Sévérité ≥ « high » pour une attaque confirmée** : une attaque confirmée ne doit pas
  être minimisée en « medium ».

### Robustesse / contraintes
- **Livraison SOAR ≥ 99 %** : les rapports atteignent bien le workflow de validation humaine.
- **CPU de l'agent Wazuh < 5 %** (règle non négociable du projet) : au-delà, risque
  d'impacter la production industrielle.

---

## 4. Comment lancer les tests

```bash
# Niveau 1 — rapide, sans Pi. Écrit docs/benchmarks/kpi-ci-latest.json
make benchmark-ci

# Niveau 2 — réel (stack + Pi allumés). Écrit docs/benchmarks/report-<date>.md
make benchmark SCENARIO=all INTENSITY=standard
#   INTENSITY=smoke    → quelques alertes (test rapide)
#   INTENSITY=standard → dizaines d'alertes
#   INTENSITY=soak     → centaines, en parallèle (test de charge "beaucoup de logs")

# Variante manuelle en deux temps :
python -m scripts.benchmark.run_attack_suite --scenario B --intensity smoke   # attaque
python -m scripts.benchmark.collect_kpis --since <T0> --until <T1>            # mesure
```

Les scénarios d'attaque (A recon, B SQLi, C XSS, D path-traversal, E command-injection,
F brute-force, …) sont définis une seule fois dans `scripts/benchmark/scenarios.py`. Les
règles à forte valeur impossibles à déclencher depuis Kali (compte AD, ransomware, C2…)
sont couvertes par le corpus étiqueté du Niveau 1.

---

## 5. Résultats actuels

### Niveau 1 (dernier `make benchmark-ci`) — tout dans les clous
| KPI | Résultat | Objectif | Statut |
|---|---|---|---|
| Rappel d'attaque | 12/12 (100 %) | ≥ 95 % | ✅ |
| Rapport JSON valide | 12/12 | 100 % | ✅ |
| Action concrète | 12/12 | 100 % | ✅ |
| Sévérité cohérente | 12/12 | ≥ high si confirmée | ✅ |
| Porte UEBA (décisions) | 6/6 | 100 % | ✅ |
| Taux de faux positifs (filtre ON) | 0 % | ≤ 5 % | ✅ |
| Taux de faux positifs (filtre OFF) | 33 % | — | ⚠️ montre l'utilité du filtre |
| Connecteur identité | OK | OK | ✅ |

Snapshot machine : `docs/benchmarks/kpi-ci-latest.json` (régénéré à chaque run, non versionné).

### Niveau 2 (premier échantillon live, 2026-06-15, SQLi, intensité smoke)
2 alertes escaladées, 1 rapport LLM complet sur le Pi :

| KPI | Mesuré | Objectif | Statut |
|---|---|---|---|
| MTTT triage p50 / p95 | 45 s / 58,5 s | p95 < 90 s | ✅ |
| Temps analyse LLM p95 | 291 s | < 600 s | ✅ |
| RAG (lecture contexte) p95 | 0,095 s | < 1 s | ✅ |
| Livraison SOAR | 100 % | ≥ 99 % | ✅ |
| Rapport JSON valide | 100 % (1/1) | 100 % | ✅ |
| Pic file de triage | 2 | ≈ 0 | ⚠️ micro-échantillon (2 alertes quasi simultanées) |

**Encore à faire** : un vrai run de charge `soak` (valider le débit / zéro perte sous des
centaines d'alertes), et les KPI **ressources du Pi** (CPU/RAM/température, via
`node_exporter`) + le **CPU agent Wazuh < 5 %**.

---

## 6. Références

- Cibles formalisées : [ADR 003](../adr/003-kpi-benchmark-protocol.md).
- Protocole MTTT avant/après : [ADR 002](../adr/002-mttt-measurement-protocol.md).
