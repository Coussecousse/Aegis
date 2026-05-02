# Node 2 - AI Appliance (Raspberry Pi 5)

This node runs Ollama with the two quantised models used by AEGIS.

## Setup (when the Raspberry Pi is available)

1. Install Ollama for ARM: https://ollama.com/download/linux
2. Pull the models:
   ```bash
   ollama pull tinyllama:1.1b
   ollama pull mistral:7b-instruct-q4_0
   ```
3. Ollama listens on port 11434 by default.
4. Make sure Node 1 can reach this host at the address set in
   `OLLAMA_HOST` in your `.env` file.

## No Docker required on Node 2
Ollama runs as a native service on the Raspberry Pi.
Docker is only used on Node 1.
