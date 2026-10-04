# AGENT.md - Threat Information Harvester Development Guidelines

This document outlines the architecture, implementation standards, development workflows, and operational procedures for the **Threat Information Harvester** project. All AI agents and human contributors must adhere to the conventions defined in this file.

---

## 1. Project Overview & Mission

### 1.1 Objective
The **Threat Information Harvester** is an automated Cyber Threat Intelligence (CTI) collection and analysis platform designed to monitor, filter, analyze, and alert on cyber threats with a primary focus on **Japan-targeted threats (日本を標的とする脅威情報)**.

### 1.2 Target Sources
1. **General Web Search & LLM Grounded Search**: Monitoring breaking cyber incidents, data leaks, and attack campaigns.
2. **Dark Web (.onion)**: Monitoring ransomware leak sites (DLS), dark web forums, and breach notification portals via Tor.
3. **Telegram Channels / Accounts**: Tracking hacker group channels, OSINT channels, and leak announcements.
4. **X (Twitter) Accounts**: Tracking security researchers, threat intelligence feeds, and incident breaking reports.
5. **Security Vendor Feeds & Advisories**: RSS/Atom feeds from Japanese CERTs (JPCERT/CC, IPA) and global security vendors/news (BleepingComputer, The Hacker News, CISA, etc.).

### 1.3 Cost & Resource Philosophy
- **Primary AI Engine**: Google Gemini API (`google-genai` SDK) utilizing available API keys.
- **Cost Efficiency**: High-cost commercial APIs (e.g., paid Twitter Enterprise API, commercial CTI feeds) are avoided. Free tiers, open-source solutions, web previews, RSS feeds, Tor proxying, and Gemini Grounded Search are prioritized.
- **Target Audience**: Security analysts and DevOps engineers operating within Kubernetes environments.

### 1.4 Open Source Software (OSS) & Commercial Use Policy
- **Open Source Release**: This project is published as open-source software under the **MIT License**.
- **Commercial Use Allowed**: Commercial use, modification, distribution, and private use are fully permitted without restriction.
- **Third-Party Dependency Compliance**: All bundled dependencies, container base images, and Helm templates must use permissive open-source licenses compatible with commercial usage (MIT, Apache 2.0, BSD, etc.). Copyleft licenses requiring disclosure of proprietary user code (e.g., AGPL) should be avoided.
- **Responsible Use & Disclaimer**: Operational adherence to [SECURITY.md](SECURITY.md) and legal compliance regarding passive OSINT/CTI collection is mandatory.

---

## 2. Architecture & System Design

```
+-----------------------------------------------------------------------------------+
|                            Threat Information Harvester                           |
+-----------------------------------------------------------------------------------+
|  Data Harvesters (Collectors)                                                     |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|  |  Vendor/CERT RSS   |  |  Gemini Web Search |  |  Tor SOCKS5 (.onion)        |  |
|  |  (JPCERT, IPA, etc)|  |  (Google Grounding)|  |  (Ransomware Leak Sites)    |  |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|  +--------------------+  +--------------------+                                   |
|  |  Telegram Monitor  |  |  X (Twitter) Feed  |                                   |
|  |  (Web preview/API) |  |  (Nitter/Grounded) |                                   |
|  +--------------------+  +--------------------+                                   |
+-----------------------------------------------------------------------------------+
                                         │ Raw Threat Data
                                         ▼
+-----------------------------------------------------------------------------------+
|  Processing & Storage Pipeline                                                    |
|  1. Normalization & Deduplication (Persistent Cache / SQLite)                     |
|  2. Gemini AI Intelligence Analysis:                                              |
|     - Target Relevance to Japan (Direct / Indirect / Global / None)               |
|     - Severity Assessment (Critical / High / Medium / Low)                         |
|     - Victim & Threat Actor Extraction                                            |
|     - Japanese Executive Summary & Actionable Recommendations                     |
+-----------------------------------------------------------------------------------+
                                         │ Enriched CTI Alert
                                         ▼
+-----------------------------------------------------------------------------------+
|  Notification & Sinks                                                             |
|  - Discord Webhooks (Priority alerts with @here for Critical)                     |
|  - JSON/File Artifacts / SQLite Audit Log                                         |
+-----------------------------------------------------------------------------------+
```

### 2.1 Directory Structure
```
.
├── AGENT.md                      # Agent and contributor instructions
├── README.md                     # Project documentation
├── LICENSE                       # MIT License (commercial use permitted)
├── SECURITY.md                   # Security policy & responsible CTI use disclaimer
├── CONTRIBUTING.md               # Open source contribution guidelines
├── Dockerfile                    # Production container image
├── Dockerfile.dev                # Development & CLI container image
├── requirements.txt              # Production Python dependencies
├── requirements-dev.txt          # Development Python dependencies
├── docs/
│   ├── task_tracker.md           # Task tracking and roadmap (required for interaction)
│   └── architecture.md           # Detailed architecture & source specifications
├── src/
│   ├── __init__.py
│   ├── cli.py                    # Unified CLI entrypoint
│   ├── config.py                 # Configuration loader (Env & ConfigMap)
│   ├── harvesters/               # Source collectors
│   │   ├── __init__.py
│   │   ├── base.py               # Abstract base harvester
│   │   ├── vendor_rss.py         # Security vendor & CERT RSS harvester
│   │   ├── web_search.py         # Gemini Search Grounding harvester
│   │   ├── darkweb_onion.py      # Tor-based .onion leak site harvester
│   │   ├── telegram.py           # Telegram channel harvester
│   │   └── x_monitor.py          # X/Twitter monitor harvester
│   ├── analyzer/                 # AI Analysis pipeline
│   │   ├── __init__.py
│   │   └── gemini_analyzer.py    # Gemini-powered CTI enrichment & Japan relevancy
│   ├── storage/                  # Deduplication & persistent state
│   │   ├── __init__.py
│   │   └── cache.py              # Cache/dedup store (SQLite/JSON)
│   └── notifiers/                # Alert destinations
│       ├── __init__.py
│       └── discord.py            # Discord webhook notifier
└── charts/
    └── information-harvester/    # Helm chart for Kubernetes deployment
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
            ├── cronjob.yaml      # Scheduled collector job
            ├── dev-pod.yaml      # Development & operational CLI container
            ├── tor-proxy.yaml    # Tor SOCKS5 proxy deployment & service
            ├── configmap.yaml    # Feed definitions & keywords
            ├── secret.yaml       # API keys and webhook secrets
            └── pvc.yaml          # Persistent storage for cache & history
```

---

## 3. Data Sources & Harvesting Strategy (Low-Cost)

1. **Vendor & CERT RSS Feeds**:
   - Focus on Japanese agencies (`JPCERT/CC`, `IPA`) and major global news (`BleepingComputer`, `The Hacker News`, `CISA`).
   - Zero-cost, high reliability.
2. **Gemini Web Search Grounding**:
   - Uses `google-genai` SDK with `GoogleSearch` tool.
   - Searches targeted queries (e.g., `"Japan ransomware victim"`, `"ランサムウェア 日本 標的"`, `"サイバー攻撃 被害"`).
   - High cost-efficiency (included within Gemini API quotas, avoiding paid search engine API subscriptions).
3. **Dark Web (.onion) via Tor**:
   - Connects through an in-cluster Tor SOCKS5 proxy container (`socks5h://tor-proxy:9050`).
   - Monitors ransomware leak site directories, public aggregation feeds (e.g., Ransomlook/ransomfeed APIs and open mirrors), and selected .onion sites.
4. **Telegram Monitoring**:
   - Primary: Public channel web preview scraping (`https://t.me/s/<channel>`), requiring no API keys or phone numbers.
   - Secondary: Telethon / Telegram Bot API integration when credentials are provided in secrets.
5. **X (Twitter) Monitoring**:
   - Primary: Gemini Grounded Search on Twitter/X security feeds, and Nitter/RSS bridge proxies.
   - Secondary: Direct API v2 if credentials are provided in secrets.

---

## 4. Kubernetes & Helm Deployment Architecture

- **Deployment Tool**: Helm 3 chart located in `charts/information-harvester`.
- **Target Cluster**: Kubernetes (k3s or standard k8s).
- **Core Components**:
  1. `CronJob` / `Deployment`: Executes periodic harvesting, analysis, and notification.
  2. `tor-proxy`: Lightweight Alpine-based Tor daemon providing SOCKS5 on port 9050.
  3. `dev-pod`: Long-running development and administrative container for debugging, manual harvests, and running CLI commands.
  4. `PVC`: Persistent volume claim for deduplication cache and historic incident storage.

---

## 5. Development Container & CLI Operations

All operational and debugging commands must be centralized in the development container.

### 5.1 CLI Command Suite (`harvester`)
- `harvester run`: Run full harvest across all enabled sources, analyze with Gemini, and dispatch alerts.
- `harvester test --source <vendor|web|tor|telegram|x>`: Test a specific source collector in isolation.
- `harvester search "<query>"`: Run a standalone Gemini Grounded Search query.
- `harvester test-onion "<url>"`: Test connectivity and scraping of an `.onion` URL through the Tor proxy.
- `harvester status`: Check connectivity, API credentials, Tor proxy status, and cache size.

### 5.2 Kubernetes Dev Pod Access
```bash
# Exec into the running dev-pod in Kubernetes
kubectl exec -it deployment/information-harvester-dev -n default -- bash

# Run CLI inside the dev container
harvester status
harvester test --source vendor
```

---

## 6. Version Control (Git Conventions)

All Git commit messages MUST be written in English following the Conventional Commits format:

```text
<type>(<scope>): <subject>

- <description item 1>
- <description item 2>
```

- **Line 1:** Concise summary of changes (~50 characters recommended).
- **Line 2:** Empty line.
- **Line 3+:** Bulleted list (`- `) detailing specific modifications.
- **Signature:** Sign all commits with GPG/SSH key (`-S` or default `commit.gpgsign=true`). Verified signatures are required.

**Example:**
```text
feat(backend): implement order processing logic

- Add ExecuteTrade method to SimulationService
- Create transaction records in DB
- Update user holdings after trade
```

---

## 7. User Interaction

- When the user asks "What should we do next?" (「次は何をすればいい？」), review `docs/task_tracker.md` and propose concrete, prioritized next steps clearly in Japanese.

---

## 8. Code & Quality Standards

1. **Language & Runtime**: Python 3.11+.
2. **Type Hints**: Use type annotations (`typing`) for public functions, methods, and dataclasses/Pydantic models.
3. **Error Handling**: Harvesters must not fail the entire batch when an external source times out or fails. Catch exceptions, log warnings, and continue processing remaining sources.
4. **Rate Limiting & Politeness**: Tor and Web scraping must respect exponential backoffs and timeouts to prevent IP bans and excessive cluster load.
5. **Security & Secrets**: Never hardcode API keys, webhook URLs, or tokens. Read from environment variables populated via Kubernetes Secrets.
