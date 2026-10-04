# Threat Information Harvester (Japan Cyber Threat Intelligence)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Next.js: 14+](https://img.shields.io/badge/Next.js-14+-black.svg)](https://nextjs.org/)
[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Supported-2496ED.svg)](docker-compose.yml)
[![Kubernetes / Helm](https://img.shields.io/badge/Kubernetes-Helm_3-326CE5.svg)](charts/information-harvester)

Automated Cyber Threat Intelligence (CTI) collection, AI analysis, SOC Dashboard, and notification platform focusing on **Japan-targeted threats and domestic incidents**.

---

## 1. Architecture & Services

The platform consists of a decoupled microservice architecture:
- **Web Dashboard (`web/`)**: Next.js 14 (TypeScript + Tailwind CSS + Lucide React) responsive Cyber SOC UI (Port 3000).
- **Backend Service (`backend/`)**: FastAPI asynchronous CTI Engine, Gemini AI analyzer, and threat collectors (Port 8000).
- **Database Engine**: PostgreSQL 16 (CNPG on k3s / container) with SQLite fallback.
- **Tor SOCKS5 Proxy**: Alpine-based in-cluster/container Tor daemon for dark web (.onion) reachability.

| Intelligence Source | Collection Method | Cost & Footprint |
| :--- | :--- | :--- |
| **Web Search Grounding** | Gemini API (`google-genai` SDK) Grounded Search | Free / Included in Gemini quota |
| **Dark Web (.onion)** | Tor SOCKS5 proxy crawler monitoring ransomware DLS | Free (via Tor proxy service) |
| **Telegram Channels** | Public web preview scraper (`t.me/s/<channel>`) | Free (no API key or phone required) |
| **X (Twitter) Feeds** | Grounded researcher feed monitoring | Low cost (no Enterprise X API required) |
| **Vendor & CERT Feeds** | JPCERT/CC, IPA, BleepingComputer, CISA, etc. | Free & highly reliable |

---

## 2. Quickstart with Docker Compose (Recommended)

Run the entire stack (Next.js Dashboard, FastAPI Backend, PostgreSQL DB, and Tor Proxy) with a single command:

```bash
# 1. Clone repository & configure environment variables (optional)
cp .env.example .env

# 2. Start all services with Docker Compose
docker compose up -d --build

# 3. Access Web Dashboard
open http://localhost:3000

# 4. Access Backend API & OpenAPI Docs
open http://localhost:8000/docs
```

Services started:
- **Next.js Web Dashboard**: `http://localhost:3000`
- **FastAPI Backend API**: `http://localhost:8000`
- **PostgreSQL Database**: `localhost:5433` (internal `db:5432`)
- **Tor SOCKS5 Proxy**: `localhost:9050` (internal `tor:9050`)

---

## 3. Local Development

### Backend (Python)
```bash
# Install virtualenv requirements
pip install -r requirements.txt

# Start API service
python app.py
# or
harvester serve --port 8000
```

### Web Dashboard (Next.js)
```bash
cd web
npm install
npm run dev
# Dashboard runs on http://localhost:3000
```

---

## 4. CLI Operations (`harvester`)

The `harvester` CLI tool is available directly in the local environment and inside containers:

```bash
# System status & probes
harvester status

# Execute harvesting pipeline across all sources
harvester run --hours 24
harvester run --hours 24 --direct-only

# Test individual collector modules
harvester test --source vendor
harvester test --source telegram
harvester test --source web

# Search threats with Gemini Search Grounding
harvester search "Japan targeted ransomware breach"

# Inspect harvested incidents
harvester history
harvester show <ID>

# Test notification sinks
harvester test-notify
harvester test-notion
```

---

## 5. Kubernetes & k3s (CloudNativePG) Deployment

Deploy to Kubernetes / k3s using Helm (`charts/information-harvester`):

```bash
helm upgrade --install information-harvester ./charts/information-harvester \
  --namespace security \
  --create-namespace \
  --set database.type="postgres" \
  --set database.existingSecret="information-harvester-db-app" \
  --set secrets.geminiApiKey="YOUR_GEMINI_API_KEY" \
  --set secrets.discordWebhookUrl="YOUR_DISCORD_WEBHOOK_URL"
```

---

## 6. Community & Guidelines

- **Agent Guidelines**: Coding guidelines and commit rules are defined in [AGENT.md](AGENT.md).
- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) for pull request workflows.
- **Task Tracking**: Progress roadmap is maintained in [docs/task_tracker.md](docs/task_tracker.md).
- **Security Policy**: See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

---

## 7. License

Released under the **[MIT License](LICENSE)**. Permissive for both commercial and private usage.
