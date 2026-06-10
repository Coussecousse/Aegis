# Raspberry Pi - Ollama Configuration & LLM Response Format

> **Version**: 0.2.0
> **Purpose**: Configure Ollama on Raspberry Pi (WireGuard node) to serve SLM (Qwen 2.5 1.5B) and LLM (Mistral 7B) for the AEGIS pipeline
> **Network**: Accessible via WireGuard tunnel only — IP `10.0.0.1`

---

## Prerequisites

- Raspberry Pi 5 (16 GB RAM)
- Ollama installed (https://ollama.ai)
- WireGuard configured and active on the Raspberry Pi
- Network connectivity verified: `ping 10.0.0.1` from the main AEGIS node

---

## Step 1: Configure Ollama Network Binding

### Critical: Make Ollama Listen on WireGuard Interface

By default, Ollama listens only on `127.0.0.1:11434` (localhost). Since the Raspberry Pi is accessed via WireGuard tunnel (`10.0.0.1`), Ollama must bind to `0.0.0.0` to accept requests on the WireGuard interface.

#### Option A: systemd service (recommended)

Edit the Ollama systemd service:

```bash
sudo systemctl edit ollama
```

Add or update the environment section:

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

Restart Ollama:

```bash
sudo systemctl restart ollama
```

Verify:

```bash
curl http://10.0.0.1:11434/api/tags
```

Security note: The Raspberry Pi nftables firewall allows only WireGuard UDP 51820 outbound. Ollama is reachable only from the tunnel (10.0.0.0/24). There is no direct Internet access.

---

## Step 2: Pull Required Models

```bash
# SLM: Qwen 2.5 1.5B (~1GB, Apache 2.0)
ollama pull qwen2.5:1.5b

# LLM: Mistral 7B Q4 (quantized, ~4GB)
ollama pull mistral
```

Verify both models are loaded:

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

## Step 3: Deploy Custom Modelfiles

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

## Step 4: Test Models via HTTP API

### Test SLM (Qwen 2.5 1.5B)

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

### Test LLM (Mistral)

```bash
curl -X POST http://10.0.0.1:11434/api/generate \
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

## Step 5: Connection from AEGIS Middleware

The middleware will connect via:

```python
OLLAMA_BASE_URL = "http://10.0.0.1:11434"
SLM_MODEL = "qwen25-aegis"
LLM_MODEL = "mistral-aegis"
```

### In `src/aegis/llm/client.py`:

```python
# The OllamaClient will:
# 1. POST to http://10.0.0.1:11434/api/generate
# 2. Pass the model name and prompt
# 3. Parse JSON response from the Modelfile-trained model
# 4. Retry on timeout (SLM: 10s | LLM: 45s)
```

---

## Troubleshooting

### Ollama not reachable from AEGIS node

```bash
# From AEGIS host, test WireGuard connectivity
ping 10.0.0.1

# Test Ollama HTTP API
curl -v http://10.0.0.1:11434/api/tags
```

If connection fails:
1. Verify WireGuard is active on Raspberry: `sudo wg show`
2. Check Ollama is listening on `0.0.0.0`: `ss -tlnp | grep 11434`
3. Check firewall rules (Raspberry Pi): `sudo nft list ruleset`

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

- **Raspberry Pi 5 (16 GB RAM)**: SLM ~2-4 alerts/sec | LLM ~0.5-1 alert/sec
- **Temperature tuning**: Lower temp = faster, deterministic | Higher temp = more nuanced
- **Quantization**: Mistral Q4 is optimized for Raspberry Pi memory constraints

---

## References

- Ollama Documentation: https://github.com/ollama/ollama
- Model Details: https://ollama.ai/library
- AEGIS Pipeline: See `src/aegis/middleware/pipeline.py`
- Environment Variables: See `.env.example`

---

**Next Steps:**
1. Run Step 1-5 on Raspberry Pi
2. Verify connectivity from main AEGIS node
3. Deploy `src/aegis/llm/client.py` on AEGIS node
4. Run integration tests: `pytest tests/integration/test_ollama_connection.py`
