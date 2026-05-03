# Runbook Wazuh — Regles custom AEGIS

## 1. Introduction

Les regles de detection custom AEGIS sont versionnees dans le depot Git dans
`docker/node1/wazuh/config/local_rules.xml`.

Elles sont chargees automatiquement au demarrage du conteneur Wazuh Manager
(montage Docker vers `/var/ossec/etc/rules/local_rules.xml`).

Aucune configuration manuelle dans le dashboard Wazuh n'est necessaire pour
creer, modifier ou deployer ces regles: la source de verite est le code.

## 2. Comment lire une alerte Wazuh

Lorsqu'une alerte est generee, verifier en priorite les champs suivants:

- `rule.id`: identifiant unique de la regle declenchee (ex: `100001`)
- `rule.level`: severite Wazuh (1 a 15)
- `rule.description`: message fonctionnel de la detection
- `rule.groups`: familles de menace (ex: `ransomware_indicator`, `policy_violation`)
- `agent.name`: machine source qui a emis l'evenement
- `timestamp`: date/heure de detection (UTC selon la configuration)

Lecture operationnelle minimale:

1. Identifier la regle (`rule.id`) et son niveau (`rule.level`).
2. Verifier l'actif impacte (`agent.name`) et la fenetre temporelle (`timestamp`).
3. Suivre l'action recommandee du tableau section 4.

## 3. Niveaux d'alerte

| Niveau Wazuh | Gravite AEGIS | Interpretation operationnelle |
|---|---|---|
| 1-6 | info | Evenement faible, supervision continue |
| 7-11 | warning | Activite anormale a qualifier rapidement |
| 12-15 | critique | Menace probable/active, escalation immediate |

## 4. Tableau des regles custom AEGIS

| ID | Niveau | Scenario BIA | Description courte | Action recommandee |
|---|---:|---|---|---|
| 100001 | 10 | S1/S2 | Multiples echecs AD en 60s | Bloquer IP source temporairement, ouvrir investigation IAM |
| 100002 | 12 | S1/S2 | Login reussi apres echecs (credential stuffing) | Forcer reset mot de passe, invalider sessions, verifier MFA |
| 100003 | 14 | S4 | Ajout a Domain/Enterprise Admins | Revoquer changement, isoler compte, lancer revue AD urgente |
| 100004 | 10 | S4 | Login Tier 0 hors horaires | Verifier legitimite, exiger justification, corriger politique d'acces |
| 100005 | 15 | S4/S8 | Compte Tier 0 utilise sur poste Tier 2 | Isoler poste, bloquer compte admin, activer cellule de crise |
| 100010 | 14 | S1 | Rafale de modifications fichiers NAS | Isoler hote source, couper partage ecriture, lancer chasse ransomware |
| 100011 | 15 | S1 | Extension ransomware detectee | Isoler immediatement l'actif, enclencher plan de reponse ransomware |
| 100012 | 12 | S1/S8 | Modif PGDATA hors fenetre backup | Geler changements DB, verifier integrite, comparer snapshots |
| 100013 | 14 | S1 | Suppression shadow copies (vssadmin/wmic/wbadmin) | Isoler machine, bloquer processus, collecter artefacts forensics |
| 100020 | 12 | S2 | Gros transfert sortant NAS (>500MB) | Couper flux sortant, valider destination, examiner utilisateur source |
| 100021 | 10 | S2 | Acces NAS hors VLAN Bureau d'Etudes | Bloquer acces reseau, verifier poste source, revue ACL VLAN |
| 100022 | 13 | S2 | `pg_dump`/`COPY TO` par non-DBA | Suspendre compte, verifier requetes et exfil potentielle |
| 100030 | 11 | S8 | Connexion `psql` directe depuis poste utilisateur | Verifier besoin metier, fermer acces direct, renforcer bastion DB |
| 100031 | 15 | S8 | Agent Wazuh deconnecte/tampering | Traiter comme tentative d'aveuglement SOC, isolation prioritaire |
| 100032 | 10 | S8 | Elevation sudo hors maintenance | Verifier changement autorise, audit commandes, corriger droits |
| 100040 | 11 | S3 | Nouveau logiciel sur serveur Tier 1 hors change | Verifier CAB/change ticket, rollback si non autorise |
| 100041 | 13 | S3 | Sortie serveur vers IP externe inconnue (C2) | Bloquer destination, analyser trafic et processus emetteur |
| 100042 | 10 | S3 | API RabbitMQ accessee depuis hote non-admin | Bloquer source, rotation credentials RabbitMQ, audit acces API |

## 5. Comment ajouter une nouvelle regle (procedure 5 etapes)

1. Editer `docker/node1/wazuh/config/local_rules.xml` et ajouter une regle avec un ID `>= 100000`.
2. Tester la syntaxe et le comportement avec `wazuh-logtest` dans le conteneur manager.
3. Committer la modification dans Git (review obligatoire).
4. Redemarrer/recreer le conteneur Wazuh Manager pour recharger les regles.
5. Verifier dans le dashboard Wazuh que la regle apparait et qu'une alerte test est generee.

Commandes utiles:

```bash
# Test de validite du moteur d'analyse
MSYS_NO_PATHCONV=1 docker exec aegis-node1-wazuh.manager-1 sh -lc '/var/ossec/bin/wazuh-analysisd -t'

# Redemarrage manager avec fichier .env du repo
cd /d/COURS/AEGIS
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d wazuh.manager
```

## 6. Comment tester une regle existante (exemple regle 100001)

Objectif: simuler des echecs d'authentification AD repetes et verifier le declenchement
`rule.id = 100001`.

```bash
# Ouvrir wazuh-logtest dans le conteneur manager
MSYS_NO_PATHCONV=1 docker exec -it aegis-node1-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Injecter plusieurs fois un evenement d'echec Windows (exemple simplifie):

```text
{"win":{"system":{"eventID":"4625"},"eventdata":{"ipAddress":"192.168.10.50","targetUserName":"j.dupont"}}}
```

Resultat attendu apres repetition dans la fenetre de 60s:

- apparition d'une alerte avec `rule.id = 100001`
- niveau `rule.level = 10`
- groupe contenant `authentication_failed`

Si la regle ne declenche pas:

1. Verifier que le log source est bien decode avec les champs attendus (`ipAddress`).
2. Verifier que la regle parent (`60122`) est declenchee avant la correlation.
3. Verifier le chargement du fichier `local_rules.xml` dans le conteneur manager.
