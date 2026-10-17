# Threat Harvester 

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go: 1.22+](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://go.dev/)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB.svg)](https://www.python.org/)
[![Next.js: 16+](https://img.shields.io/badge/Next.js-16+-black.svg)](https://nextjs.org/)
[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Supported-2496ED.svg)](docker-compose.yml)
[![Kubernetes / Helm](https://img.shields.io/badge/Kubernetes-Helm_3-326CE5.svg)](charts/threat-harvester)
[![CI / Quality Gates](https://github.com/al17091/threat_harvester/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/al17091/threat_harvester/actions/workflows/docker-publish.yml)

## Japan Cyber Threat Intelligence Feeds Collector

Automated Cyber Threat Intelligence (CTI) collection, Hybrid AI analysis (LiteLLM Qwen2.5-3B + Gemini Escalation), Cyber SOC Dashboard, and notification platform focusing on **Japan-targeted threats and domestic incidents**.

---

## 1. Architecture & Services

The platform consists of a decoupled microservice architecture (orchestrated via Docker Compose or Helm using `ghcr.io/al17091/threat_harvester`):
- **Web Dashboard (`web/`, tag `web-<version>`)**: Next.js 16 (TypeScript + Tailwind CSS + Lucide React) responsive Cyber SOC UI (`/en`, `/ja` on Port 3000).
- **API Engine (`api/`, tag `api-<version>` / `backend-<version>`)**: High-performance Go 1.22+ CTI Engine, Hybrid AI analyzer (LiteLLM OpenAI-compatible + Gemini API escalation), async article scraper, and REST API (Port 8000).
- **Harvester & Analysis Worker (`worker/`, tag `worker-<version>`)**: Python 3.12+ extensible crawler worker and batch processor for continuous CTI enrichment.
- **Database Engine**: PostgreSQL 16 (CloudNativePG on k3s / container) with pure-Go SQLite fallback.
- **Tor SOCKS5 Proxy**: External or in-cluster Tor SOCKS5h proxy for dark web (`.onion`) reachability.

| Intelligence Source | Collection Method | Cost & Footprint |
| :--- | :--- | :--- |
| **SearXNG Cross-Search** | Metasearch across Ahmia, Torch (.onion), and Clearnet News/Web | Free (Self-hosted SearXNG JSON API) |
| **Web Search Grounding** | Gemini API (`gemini-3.5-flash-lite`) Grounded Search (4h throttled) | Low cost / Included in Gemini quota |
| **Dark Web (.onion)** | Tor SOCKS5h proxy crawler & Ahmia search monitoring ransomware DLS | Free (via Tor proxy service) |
| **Ransomware Trackers** | Ransomlook API & RansomFeed RSS tracking global/domestic victims | Free & real-time |
| **Telegram Channels** | Public web preview scraper (`t.me/s/<channel>`) + recursive link scraper | Free (no API key or phone required) |
| **X (Twitter) Feeds** | Grounded researcher & domestic security feed monitoring | Low cost (no Enterprise X API required) |
| **Vendor & CERT Feeds** | JPCERT/CC, IPA, ScanNetSecurity, Security Next, CISA KEV, BleepingComputer | Free & highly reliable |

---

## 2. Quickstart with Docker Compose

Run the stack (Next.js Dashboard, Go API Engine, Python Worker, and PostgreSQL DB) with a single command:

```bash
# 1. Configure environment variables
cp .env.example .env

# 2. Start all services with Docker Compose
docker compose up -d --build

# 3. Access Web Dashboard (supports both root "/" and subpath e.g. "/thhv")
open http://localhost:3000/thhv
open http://localhost:3000/thhv/ja

# 4. Access Backend API Status & RSS Feed
open http://localhost:3000/thhv/api/status
open http://localhost:3000/thhv/rss
```

---

## 3. Container Image Build & Release Workflow (GHCR)

Images are published to `ghcr.io/al17091/threat_harvester` using Semantic Versioning (`VERSION` file) via GitHub Actions ([`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)):
- **`main` branch / release tag (`v0.1.0`)**:
  - `ghcr.io/al17091/threat_harvester:api-0.1.0` (also tagged `backend-0.1.0`)
  - `ghcr.io/al17091/threat_harvester:worker-0.1.0`
  - `ghcr.io/al17091/threat_harvester:web-0.1.0`
- **`develop` branch (automatic `-preview` suffix)**:
  - `ghcr.io/al17091/threat_harvester:api-0.0.5-preview`
  - `ghcr.io/al17091/threat_harvester:worker-0.0.5-preview`
  - `ghcr.io/al17091/threat_harvester:web-0.0.5-preview`

You can also build and push manually using [`scripts/build_and_push.sh`](scripts/build_and_push.sh):

```bash
# Build & push using VERSION file (auto-appends -preview on develop branch)
./scripts/build_and_push.sh al17091

# Specify explicit SemVer version
./scripts/build_and_push.sh al17091 0.1.0 all
./scripts/build_and_push.sh al17091 0.0.5-preview all
```

---

## 4. CLI Operations (`harvester`)

The `harvester` CLI tool is available via `./scripts/harvester.sh` locally and as `harvester` inside containers:

```bash
# System status & database statistics
harvester status

# Execute a single harvesting & enrichment cycle
harvester run
harvester run --lookback 24 --direct-only

# Start continuous cron loop
harvester cron

# Inspect harvested incidents
harvester history --limit 20 --japan-only
harvester show <ID>

# Test notification & Notion sinks
harvester test-notify
harvester test-notion
```

---

## 5. Kubernetes & k3s (CloudNativePG) Deployment

Deploy the separated `backend` (`backend-0.1.0`) and `dashboard` (`web-0.1.0`) services to Kubernetes / k3s using Helm (`charts/threat-harvester`):

```bash
helm upgrade --install threat-harvester ./charts/threat-harvester \
  --namespace security \
  --create-namespace \
  --set backend.image.tag="backend-0.1.0" \
  --set dashboard.image.tag="web-0.1.0" \
  --set database.type="postgres" \
  --set database.existingSecret="threat-harvester-db-app" \
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

## 7. Disclaimer & Commercial Usage Notice

- **Non-Commercial Usage Notice**:
  - By default, this tool and the public demonstration site include **non-commercial data collection modules** (such as public web scraping for X / Telegram and dark web crawling via Tor). Therefore, **this tool cannot be used for commercial purposes as-is**.
  - **For Corporate or Commercial Use**: Please fork this repository and replace the X (Twitter), Telegram, and Dark Web scraping collectors with **commercially licensed official APIs or commercial threat intelligence feeds** before deploying in a corporate environment.
- **General Disclaimer**:
  - This software and all collected/analyzed threat intelligence are provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to accuracy, completeness, or timeliness. Use strictly for defensive security research and threat monitoring purposes.


---

## 8. License & Copyright

- Source code is licensed under the **[MIT License](LICENSE)** (note the third-party data source restrictions in Section 7 above).
- Copyright &copy; 2026 Koki Higashi (`al17091`). All rights reserved.
