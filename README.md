# 🛡️ CloudSentinel-MCP

**Autonomous Cloud Security Operations Agent**

An air-gapped, zero-cost security operations platform combining the Model Context Protocol (MCP), local Small Language Models (Ollama + Qwen 2.5), and a tamper-evident cryptographic audit ledger (SHA-256 hash chain).

## Architecture

```
[ Simulated Attack Events ]
         │
         ▼
[ FastAPI Ingestion Server ]
         │
         ▼
[ SQLite Database ] ◄──► [ Tamper-Evident SHA-256 Ledger ]
         │
         ▼
[ MCP Tool Interface ]
         │
         ▼
[ Local LLM (Ollama + Qwen 2.5-7B) ]
         │
         ▼
[ Streamlit War-Room Dashboard ]
```

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Pull the local AI model
```bash
ollama pull qwen2.5:7b-instruct
```

### 3. Start the server
```bash
python app/server.py
```

### 4. Launch the dashboard (new terminal)
```bash
streamlit run app/dashboard.py
```

### 5. Simulate attacks (new terminal)
```bash
python app/attacker.py --attack full_scenario
```

## Attack Types

| Command | Description |
|---------|-------------|
| `--attack brute_force` | SSH brute-force login attempts |
| `--attack sql_injection` | SQL injection in HTTP parameters |
| `--attack port_scan` | Rapid port scanning |
| `--attack data_exfil` | Data exfiltration via DNS tunneling |
| `--attack api_abuse` | API token misuse and privilege escalation |
| `--attack full_scenario` | All attacks in sequence (best for demo) |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/events` | POST | Ingest a security event |
| `/events` | GET | List all events |
| `/events/{id}` | GET | Get specific event |
| `/analyze/{id}` | POST | Run local LLM analysis on an event |
| `/ledger` | GET | View cryptographic audit chain |
| `/verify` | GET | Verify ledger integrity |
| `/tamper-demo` | POST | Deliberately tamper a block (demo) |
| `/docs` | GET | Interactive API documentation |

## Tech Stack

- **Python** — Core runtime
- **FastAPI** — REST API server
- **SQLite** — Persistent event and ledger storage
- **SHA-256 Hash Chain** — Tamper-evident cryptographic audit trail
- **Ollama + Qwen 2.5-7B** — Local AI inference (zero cloud cost)
- **Streamlit** — Real-time war-room dashboard
- **Model Context Protocol (MCP)** — Standardized agent tool interface

## Budget: ₹0
Entirely free and open-source. Runs offline on any Windows/Mac/Linux laptop.
