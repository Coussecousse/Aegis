# Raspberry Pi - Ollama Configuration & LLM Response Format

> **Version**: 0.3.0
> **Purpose**: Configure two partitioned Ollama instances on the Raspberry Pi (WireGuard
> node) — one for SLM triage (Qwen 2.5 1.5B), one for LLM analysis (Mistral 7B) — for
> the AEGIS pipeline
> **Network**: Accessible via WireGuard tunnel only — IP `10.0.0.1`

---

## Deployment Status

✅ **Deployed and verified on the Raspberry Pi — 2026-06-10**

- Steps 1-2: `ollama.service` disabled, `ollama-slm` and `ollama-llm` systemd units
  created and enabled — both `active (running)`
- Step 3: both instances respond `200 OK` on `/api/tags` over WireGuard
  (`curl http://10.0.0.1:11434/api/tags` and `curl http://10.0.0.1:11435/api/tags`)
- Steps 4-5: shared model store confirmed on both ports —
  `qwen2.5:1.5b`, `qwen25-aegis`, `mistral-aegis` all present, no re-pull needed
- Step 6 (LLM round-trip): `mistral-aegis` inference on `ollama-llm` exceeds 60s —
  use a generous client timeout (`-m 600` or more) when testing manually, see
  Performance Notes (~5-10 min per analysis)

---

## Architecture: Two Partitioned Ollama Instances

A single shared Ollama instance means a 5-10 minute LLM analysis and SLM triage compete
for the same CPU and the same request queue — in practice this fully serializes them,
so triage stalls and the `aegis.triage` queue backs up for the entire duration of an
LLM analysis.

To avoid this, the Raspberry Pi 5 (4 cores) runs **two independent `ollama serve`
processes**, each pinned to its own CPU cores via systemd `AllowedCPUs`:

| Instance | Port | CPU cores | Model | Used by |
|---|---|---|---|---|
| `ollama-slm` | 11434 | 1 (core 0) | `qwen25-aegis` (Qwen 2.5 1.5B) | Triage consumer (`aegis.triage`) |
| `ollama-llm` | 11435 | 3 (cores 1-3) | `mistral-aegis` (Mistral 7B Q4) | Analysis consumer (`aegis.reports`) |

Both processes share the same model store (read-only access, no conflicts) and are
reachable over WireGuard at `10.0.0.1:11434` and `10.0.0.1:11435`. The AEGIS middleware
points each consumer at its own instance via `OLLAMA_SLM_BASE_URL` /
`OLLAMA_LLM_BASE_URL` (see `.env.example`) — there is no shared lock between them.

---

## Prerequisites

- Raspberry Pi 5 (16 GB RAM, 4 cores)
- Ollama installed (https://ollama.ai) — the official installer creates a single
  `ollama.service` systemd unit, which this guide replaces with two instances
- WireGuard configured and active on the Raspberry Pi
- Network connectivity verified: `ping 10.0.0.1` from the main AEGIS node

---

## Step 1: Inspect the Existing Service

The official installer's `ollama.service` listens on `127.0.0.1:11434` by default
and will be replaced by the two units below. Note its `ExecStart`, `User` and
`Group` — the new units reuse them:

```bash
systemctl cat ollama
```

(The official installer typically uses `ExecStart=/usr/local/bin/ollama serve`,
`User=ollama`, `Group=ollama`. Adjust the units below if your Pi differs.)

---

## Step 2: Create the SLM and LLM systemd Units

Run these commands as-is on the Raspberry Pi — they create both unit files via
heredoc, no manual editing required:

```bash
sudo tee /etc/systemd/system/ollama-slm.service > /dev/null <<'EOF'
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

sudo tee /etc/systemd/system/ollama-llm.service > /dev/null <<'EOF'
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
```

`AllowedCPUs` is a cgroup v2 `cpuset` directive (systemd ≥ 244, the default on
Debian 13) — it confines each process to the listed cores. `CPUAffinity=` is an
older `sched_setaffinity`-based alternative with the same effect if `AllowedCPUs`
is unavailable on your systemd version.

Both units omit `OLLAMA_MODELS`, so they default to the same model store
(`/usr/share/ollama/.ollama/models` when running as the `ollama` user) — `ollama
serve` only reads model files during inference, so two instances can share the
store safely.

Reload systemd, switch off the default service, and start both new instances:

```bash
sudo systemctl daemon-reload
sudo systemctl disable --now ollama
sudo systemctl enable --now ollama-slm ollama-llm
```

Security note: The Raspberry Pi nftables firewall allows only WireGuard UDP 51820
outbound. Both instances are reachable only from the tunnel (10.0.0.0/24). There is
no direct Internet access.

---

## Step 3: Verify Network Binding and CPU Pinning

```bash
# Both units active (running)
systemctl status ollama-slm ollama-llm --no-pager

# Both instances listening on all interfaces
ss -tlnp | grep -E '11434|11435'

# From the AEGIS node, over WireGuard
curl http://10.0.0.1:11434/api/tags
curl http://10.0.0.1:11435/api/tags

# CPU pinning took effect
systemctl show ollama-slm -p AllowedCPUs
systemctl show ollama-llm -p AllowedCPUs
cat /sys/fs/cgroup/system.slice/ollama-slm.service/cpuset.cpus.effective
cat /sys/fs/cgroup/system.slice/ollama-llm.service/cpuset.cpus.effective
```

---

## Step 4: Pull Required Models

```bash
# SLM: Qwen 2.5 1.5B (~1GB, Apache 2.0)
ollama pull qwen2.5:1.5b

# LLM: Mistral 7B Q4 (quantized, ~4GB)
ollama pull mistral
```

Verify both models are loaded (either instance — they share the model store):

```bash
ollama list
```

Expected output:

```
NAME          ID              SIZE     MODIFIED
mistral       ...             4.1 GB   ...
qwen2.5:1.5b  ...             986 MB   ...
```

---

## Step 5: Deploy Custom Modelfiles

Copy the official Modelfiles to the Raspberry Pi by hand, then deploy them.

```bash
# On the Raspberry Pi
ollama create qwen25-aegis -f ~/Modelfile.slm-qwen25
ollama create mistral-aegis -f ~/Modelfile.llm-mistral
```

Verify that both models are present:

```bash
ollama list
```

---

## Step 6: Test Models via HTTP API

### Test SLM (Qwen 2.5 1.5B) — `ollama-slm`, port 11434

```bash
curl -X POST http://10.0.0.1:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen25-aegis",
    "prompt": "ALERT DATA:\nrule_id=1234 level=8/15\ndescription=Account creation\nagent=DC-01 ip=10.0.0.5\ndecoder=windows-eventlog mitre=T1136\nraw_log=net.exe user admin /add\n\nOUTPUT: JSON triage with fields is_suspect, confidence, behavior_category, reasoning_short, raw_probabilities.",
    "stream": false
  }'
```

Expected response (JSON only):

```json
{
  "response": "{\"is_suspect\": true, \"confidence\": 0.85, \"behavior_category\": \"privilege_escalation\", \"reasoning_short\": \"Unauthorized account creation\", \"raw_probabilities\": {\"suspect\": 0.85, \"benign\": 0.15}}"
}
```

### Test LLM (Mistral) — `ollama-llm`, port 11435

```bash
curl -X POST http://10.0.0.1:11435/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-aegis",
    "prompt": "Analyze: Lateral movement via SMB on DC-01. Original rule level: 8. Asset criticality: tier0.",
    "stream": false
  }'
```

Expected response (JSON only):

```json
{
  "response": "{\"attack_confirmed\": true, \"confidence\": 0.92, \"attack_type\": \"Lateral movement via SMB\", \"severity\": \"critical\", \"affected_asset\": \"DC-01\", \"asset_criticality\": \"tier0\", \"plain_language_summary\": \"Attacker is moving between systems. This is a critical threat to domain infrastructure.\", \"recommended_action\": \"Isolate the source workstation immediately.\", \"requires_human_validation\": true, \"raw_probabilities\": {\"attack\": 0.92, \"false_positive\": 0.08}}"
}
```

---

## Step 7: Connection from AEGIS Middleware

The middleware connects each consumer to its own instance via:

```python
OLLAMA_SLM_BASE_URL = "http://10.0.0.1:11434"  # triage consumer (qwen25-aegis)
OLLAMA_LLM_BASE_URL = "http://10.0.0.1:11435"  # analysis consumer (mistral-aegis)
SLM_MODEL = "qwen25-aegis"
LLM_MODEL = "mistral-aegis"
```

### In `src/aegis/llm/client.py`:

```python
# Each OllamaClient is constructed with a single instance's base_url and:
# 1. POSTs to {base_url}/api/generate
# 2. Passes the model name and prompt
# 3. Parses JSON response from the Modelfile-trained model
# 4. Retries on timeout (SLM: 10s | LLM: 45s)
```

---

## Troubleshooting

### Ollama not reachable from AEGIS node

```bash
# From AEGIS host, test WireGuard connectivity
ping 10.0.0.1

# Test Ollama HTTP API (SLM and LLM)
curl -v http://10.0.0.1:11434/api/tags
curl -v http://10.0.0.1:11435/api/tags
```

If connection fails:
1. Verify WireGuard is active on Raspberry: `sudo wg show`
2. Check both instances are listening on `0.0.0.0`: `ss -tlnp | grep -E '11434|11435'`
3. Check unit status: `systemctl status ollama-slm ollama-llm`
4. Check firewall rules (Raspberry Pi): `sudo nft list ruleset`

### One instance is slow despite CPU partitioning

Confirm `AllowedCPUs` actually took effect (see Step 3) — if `cpuset.cpus.effective`
shows all cores for both units, the cgroup v2 `cpuset` controller may not be
delegated to `system.slice`. Check with:

```bash
cat /sys/fs/cgroup/system.slice/cgroup.controllers
```

`cpuset` must appear in the list.

### Model returns non-JSON response

The model may be ignoring the Modelfile system prompt. Verify:

```bash
# Check the Modelfile was applied
ollama show qwen25-aegis
```

If the system prompt is missing:
1. Re-create the model: `ollama rm qwen25-aegis`
2. Re-deploy: `ollama create qwen25-aegis -f /path/to/Modelfile.slm-qwen25`

### Response too long / truncated

Adjust `PARAMETER num_predict` in the Modelfile:
- **SLM (Qwen 2.5 1.5B)**: 150-200 tokens (JSON ~180 tokens)
- **LLM (Mistral)**: 400-500 tokens (JSON + explanation ~400 tokens)

---

## Performance Notes

- **SLM instance (1 core)**: Qwen 2.5 1.5B, ~8-18s per triage call
- **LLM instance (3 cores)**: Mistral 7B Q4, ~5-10 min per analysis call
- Partitioning means an in-flight LLM analysis no longer delays SLM triage —
  triage continues at its normal pace on its own dedicated core
- **Temperature tuning**: Lower temp = faster, deterministic | Higher temp = more nuanced
- **Quantization**: Mistral Q4 is optimized for Raspberry Pi memory constraints

---

## References

- Ollama Documentation: https://github.com/ollama/ollama
- Model Details: https://ollama.ai/library
- systemd `AllowedCPUs`: `man systemd.resource-control`
- AEGIS Pipeline: See `src/aegis/middleware/pipeline.py`
- Environment Variables: See `.env.example`

---

**Next Steps:**
1. Run Steps 1-7 on Raspberry Pi
2. Verify connectivity from main AEGIS node (both ports)
3. Deploy `src/aegis/llm/client.py` on AEGIS node
4. Run integration tests: `pytest tests/integration/test_ollama_connection.py`
