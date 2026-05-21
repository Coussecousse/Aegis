# Raspberry Pi - Ollama Configuration & LLM Response Format

> **Version**: 0.2.0
> **Purpose**: Configure Ollama on Raspberry Pi (WireGuard node) to serve SLM (TinyLlama) and LLM (Mistral 7B) for the AEGIS pipeline
> **Network**: Accessible via WireGuard tunnel only — IP `10.0.0.1`

---

## Prerequisites

- Raspberry Pi 5 (16 Go RAM)
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

Note sécurité : Le firewall nftables du Raspberry Pi autorise uniquement WireGuard UDP 51820 en sortie. Ollama n'est accessible que depuis le tunnel (10.0.0.0/24). Aucun accès internet direct.

---

## Step 2: Pull Required Models

```bash
# SLM: TinyLlama (1.1B parameters, ~600MB)
ollama pull tinyllama

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
tinyllama     ...             637 MB   ...
```

---

## Step 3: Deploy Custom Modelfiles

Les Modelfiles officiels sont versionnés dans docs/modelfiles/. Copie-les sur le Raspberry Pi et déploie-les :

```bash
# Depuis Node 1, copier les Modelfiles vers le Raspberry Pi
scp docs/modelfiles/Modelfile.slm-tinyllama kika@10.0.0.1:~/Modelfile.slm
scp docs/modelfiles/Modelfile.llm-mistral kika@10.0.0.1:~/Modelfile.llm

# Sur le Raspberry Pi
ollama create tinyllama-aegis -f ~/Modelfile.slm
ollama create mistral-aegis -f ~/Modelfile.llm
```

Vérifie ensuite que les deux modèles sont présents :

```bash
ollama list
```

---

## Step 4: Test Models via HTTP API

### Test SLM (TinyLlama)

```bash
curl -X POST http://10.0.0.1:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "tinyllama-aegis",
    "prompt": "{\"rule_id\": 1234, \"rule_level\": 8, \"full_log\": \"net.exe user admin /add\"}",
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
SLM_MODEL = "tinyllama-aegis"
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
ollama show tinyllama-aegis
```

If the system prompt is missing:
1. Re-create the model: `ollama rm tinyllama-aegis`
2. Re-deploy: `ollama create tinyllama-aegis -f /path/to/Modelfile.slm`

### Response too long / truncated

Adjust `PARAMETER num_predict` in the Modelfile:
- **SLM (TinyLlama)**: 200-300 tokens (JSON ~200 tokens)
- **LLM (Mistral)**: 400-500 tokens (JSON + explanation ~400 tokens)

---

## Performance Notes

- **Raspberry Pi 5 (16 Go RAM)**: SLM ~2-4 alertes/sec | LLM ~0.5-1 alerte/sec
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
