# Task Tracker - Threat Information Harvester

## Overview
Status tracking and milestone roadmap for the **Threat Information Harvester** project.

---

## Current Status
- **Current Version**: `v0.1.0`
- **Current Phase**: Phase 6 Completed (v0.1.0 Release Preparation, GHCR CI/CD Workflow, Helm Split Services, and Hybrid AI Pipeline)
- **Last Updated**: 2026-10-17

---

## Milestone Roadmap

### Phase 1: Foundation & Architecture Setup
- [x] Establish `AGENT.md` specifications, Git conventions, and interaction guidelines.
- [x] Initialize Git repository with signed Conventional Commits.
- [x] Create project task tracker (`docs/task_tracker.md`).
- [x] Refactor codebase structure into modular hierarchy (Harvesters, Analyzer, Notifiers, Storage, CLI).
- [x] Implement Unified CLI (`scripts/harvester.sh`) for centralized command execution.
- [x] Create development container configuration (`Dockerfile.dev`).
- [x] Initialize Helm Chart structure (`charts/threat-harvester/`) with Tor proxy, CronJob, and Dev Pod support.

### Phase 2: Core Harvesters & Enrichment Implementation
- [x] **Vendor & CERT RSS Harvester**: Japanese feeds (JPCERT/CC, IPA, ScanNetSecurity, Security Next) & global feeds.
- [x] **Gemini Web Search Grounding Harvester**: Targeted threat hunting using Gemini Search Grounding.
- [x] **Dark Web (.onion) Harvester via Tor**: SOCKS5 proxy connectivity and SearXNG / ransomware leak site monitoring.
- [x] **Telegram Monitor Harvester**: Public channel web-preview scraper (`t.me/s/<channel>`) and recursive link extraction.
- [x] **X (Twitter) Monitor Harvester**: Low-cost grounded search monitoring security researcher posts.
- [x] **AI Intelligence Enrichment**: Structured schema (Severity, Japan Relevance, Victims, Actors, Recommended Actions, MITRE ATT&CK TTPs).
- [x] **Persistent Cache & Notifications**: PostgreSQL / SQLite deduplication & Discord/Slack/Webhook notifications.

### Phase 3: Reporting & Notification Expansion
- [x] Establish **MIT License** with non-commercial third-party collector notice.
- [x] Create **SECURITY.md** with responsible CTI use disclaimer and vulnerability reporting policy.
- [x] Create **CONTRIBUTING.md** defining PR workflow, quality checks, and Conventional Commits.
- [x] Implement **Notion Reporter** to auto-create incident pages in Notion databases.
- [x] Implement **Slack Webhook** and **Generic JSON Webhook** notifiers.
- [x] Implement CLI commands (`harvester status`, `harvester run`, `harvester cron`, `harvester history`, `harvester show`, `harvester test-notify`, `harvester test-notion`).

### Phase 4: Unified Config & CloudNativePG Storage
- [x] **Unified YAML Configuration (`config.yaml`)**:
  - Connection endpoints, DB, credentials, sinks, scraper, and sources configured in `config.yaml` (`config.example.yaml` template).
  - Supports `${ENV_VAR}` and `${ENV_VAR:-default}` dynamic environment variable expansion.
- [x] **Multi-Database Support (PostgreSQL / CloudNativePG & SQLite)**:
  - Storage layer supporting PostgreSQL (CNPG on k3s) and pure-Go SQLite fallback.
- [x] **Kubernetes / Helm Enhancements**:
  - CloudNativePG (`Cluster` CRD) secret integration and separated Backend/Dashboard deployments.

### Phase 5: Decoupled Full-Stack Architecture, Next.js SOC Dashboard & Go Backend
- [x] **Service Decoupling (`backend/` & `web/`)**:
  - High-performance Go 1.22+ CTI Engine (`backend/`) and Next.js 14 Cyber SOC Dashboard (`web/`).
- [x] **Hybrid AI Engine & Async Article Scraper**:
  - LiteLLM (`Qwen2.5-3B-Instruct`) primary analysis with automatic Gemini escalation (`gemini-3.5-flash-lite`) for long-context and Critical/Japan-Direct incidents.
  - Background worker pools for Clearnet and Tor (`.onion`) full-text article scraping.
- [x] **Next.js 14 Cyber SOC Web Dashboard (`web/`)**:
  - Bilingual (`/en` and `/ja`) incident feed, kill-chain grouping, STIX 2.1 bundle export, and RSS 2.0 feeds (`/rss`).
  - Session-authenticated admin operations and API route protection.
  - Custom brand SVG/ICO favicons and footer legal/non-commercial usage disclaimer.

### Phase 6: Release Packaging & CI/CD Automation (`v0.1.0`)
- [x] **GHCR Container Publishing Workflow (`.github/workflows/docker-publish.yml`)**:
  - Automated quality checks (Go tests, Next.js production build, Helm lint).
  - Publishes separated `backend-<version>` and `web-<version>` images to `ghcr.io/al17091/threat_harvester`.
  - Automatically appends `-preview` suffix for builds from the `develop` branch.
- [x] **Unified Helper Scripts (`scripts/`)**:
  - `scripts/build_and_push.sh` and `scripts/harvester.sh`.
