# Wazuh Runbook - AEGIS Custom Rules

## 1. Introduction

The AEGIS custom detection rules are versioned in the Git repository at
`docker/node1/wazuh/config/local_rules.xml`.

They are loaded automatically when the Wazuh Manager container starts
(Docker mount to `/var/ossec/etc/rules/local_rules.xml`).

No manual configuration in the Wazuh dashboard is required to create, modify,
or deploy these rules: the source of truth is the code.

## 2. How to Read a Wazuh Alert

When an alert is generated, check the following fields first:

- `rule.id`: unique identifier of the triggered rule (e.g. `100001`)
- `rule.level`: Wazuh severity (1 to 15)
- `rule.description`: functional detection message
- `rule.groups`: threat families (e.g. `ransomware_indicator`, `policy_violation`)
- `agent.name`: source machine that emitted the event
- `timestamp`: detection date/time (UTC depending on configuration)

Minimum operational reading:

1. Identify the rule (`rule.id`) and its level (`rule.level`).
2. Check the impacted asset (`agent.name`) and the time window (`timestamp`).
3. Follow the recommended action in section 4.

## 3. Alert Levels

| Wazuh level | AEGIS severity | Operational interpretation |
|---|---|---|
| 1-6 | info | Low-level event, continue monitoring |
| 7-11 | warning | Abnormal activity to assess quickly |
| 12-15 | critical | Probable/active threat, immediate escalation |

## 4. AEGIS Custom Rules Table

| ID | Level | BIA scenario | Short description | Recommended action |
|---|---:|---|---|---|
| 100001 | 10 | S1/S2 | Multiple AD failures in 60s | Temporarily block the source IP, open an IAM investigation |
| 100002 | 12 | S1/S2 | Successful login after failures (credential stuffing) | Force password reset, invalidate sessions, check MFA |
| 100003 | 14 | S4 | Added to Domain/Enterprise Admins | Revert change, isolate account, launch urgent AD review |
| 100004 | 10 | S4 | Tier 0 login outside business hours | Verify legitimacy, require justification, fix access policy |
| 100005 | 15 | S4/S8 | Tier 0 account used on a Tier 2 workstation | Isolate workstation, block admin account, activate crisis response |
| 100010 | 14 | S1 | Burst of NAS file modifications | Isolate source host, disable write share, start ransomware hunt |
| 100011 | 15 | S1 | Ransomware extension detected | Immediately isolate the asset, trigger the ransomware response plan |
| 100012 | 12 | S1/S8 | PGDATA modification outside backup window | Freeze DB changes, check integrity, compare snapshots |
| 100013 | 14 | S1 | Shadow copy deletion (vssadmin/wmic/wbadmin) | Isolate machine, block process, collect forensic artifacts |
| 100020 | 12 | S2 | Large outbound NAS transfer (>500MB) | Stop outbound flow, validate destination, inspect source user |
| 100021 | 10 | S2 | NAS access outside the Engineering VLAN | Block network access, verify source machine, review VLAN ACLs |
| 100022 | 13 | S2 | `pg_dump`/`COPY TO` by a non-DBA | Suspend account, review queries and potential exfiltration |
| 100030 | 11 | S8 | Direct `psql` connection from a user workstation | Verify business need, close direct access, strengthen the DB bastion |
| 100031 | 15 | S8 | Wazuh agent disconnected/tampering | Treat as an attempt to blind the SOC, prioritize isolation |
| 100032 | 10 | S8 | Sudo elevation outside maintenance window | Verify the approved change, audit commands, fix permissions |
| 100040 | 11 | S3 | New software on a Tier 1 server outside change control | Verify CAB/change ticket, roll back if unauthorized |
| 100041 | 13 | S3 | Server outbound traffic to an unknown external IP (C2) | Block destination, analyze traffic and source process |
| 100042 | 10 | S3 | RabbitMQ API accessed from a non-admin host | Block source, rotate RabbitMQ credentials, audit API access |

## 5. How to Add a New Rule (5-step procedure)

1. Edit `docker/node1/wazuh/config/local_rules.xml` and add a rule with an ID `>= 100000`.
2. Test syntax and behavior with `wazuh-logtest` in the manager container.
3. Commit the change to Git (review required).
4. Restart/recreate the Wazuh Manager container to reload the rules.
5. Verify in the Wazuh dashboard that the rule appears and a test alert is generated.

Useful commands:

```bash
# Test analysis engine validity
MSYS_NO_PATHCONV=1 docker exec aegis-node1-wazuh.manager-1 sh -lc '/var/ossec/bin/wazuh-analysisd -t'

# Restart the manager using the repo .env file
cd /d/COURS/AEGIS
docker compose -f docker/node1/docker-compose.yml --env-file .env up -d wazuh.manager
```

## 6. How to Test an Existing Rule (example rule 100001)

Goal: simulate repeated AD authentication failures and verify the trigger
`rule.id = 100001`.

```bash
# Open wazuh-logtest in the manager container
MSYS_NO_PATHCONV=1 docker exec -it aegis-node1-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Inject the same Windows failure event several times (simplified example):

```text
{"win":{"system":{"eventID":"4625"},"eventdata":{"ipAddress":"192.168.10.50","targetUserName":"j.dupont"}}}
```

Expected result after repetition within the 60-second window:

- an alert appears with `rule.id = 100001`
- level `rule.level = 10`
- a group containing `authentication_failed`

If the rule does not trigger:

1. Verify that the source log is decoded with the expected fields (`ipAddress`).
2. Verify that the parent rule (`60122`) triggers before correlation.
3. Verify that `local_rules.xml` is loaded in the manager container.
