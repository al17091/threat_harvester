# Task Tracker - Threat Information Harvester

## Overview
Status tracking for the **Threat Information Harvester** project. This file is referenced whenever planning or proposing the next actions.

---

## Current Status
- **Current Phase**: Phase 5 Completed (Docker Compose, Next.js Web Dashboard, and Decoupled Architecture)
- **Last Updated**: 2026-10-04

---

## Milestone Roadmap

### Phase 1: Foundation & Architecture Setup
- [x] Establish `AGENT.md` specifications, Git conventions, and interaction guidelines.
- [x] Initialize Git repository with proper conventions.
- [x] Create project task tracker (`docs/task_tracker.md`).
- [x] Refactor codebase structure into modular hierarchy (Harvesters, Analyzer, Notifiers, Storage, CLI).
- [x] Implement Unified CLI (`bin/harvester`) for centralized command execution.
- [x] Create development container configuration (`Dockerfile.dev`).
- [x] Initialize Helm Chart structure (`charts/information-harvester/`) with Tor proxy, CronJob, and Dev Pod support.

### Phase 2: Core Harvesters & Enrichment Implementation
- [x] **Vendor & CERT RSS Harvester**: Japanese feeds (JPCERT/CC, IPA, ScanNetSecurity, Security Next) & global feeds.
- [x] **Gemini Web Search Grounding Harvester**: Targeted threat hunting using Gemini Search Grounding.
- [x] **Dark Web (.onion) Harvester via Tor**: SOCKS5 proxy connectivity and ransomware leak site monitoring.
- [x] **Telegram Monitor Harvester**: Public channel web-preview scraper (`t.me/s/<channel>`).
- [x] **X (Twitter) Monitor Harvester**: Low-cost Grounded search monitoring researcher posts.
- [x] **Gemini Intelligence Enrichment**: Structured schema (Severity, Japan Relevance, Victims, Actors, Action items).
- [x] **Persistent Cache & Notifications**: SQLite deduplication & Discord notifications with Japan-target highlight flags.

### Phase 3: Reporting & Notification Expansion
- [x] Establish **MIT License** explicitly permitting commercial and non-commercial usage.
- [x] Create **SECURITY.md** with responsible CTI use disclaimer and vulnerability reporting policy.
- [x] Create **CONTRIBUTING.md** defining PR workflow, quality checks, and Conventional Commits.
- [x] Implement **Notion Reporter** (`backend/reporters/notion_reporter.py`) to auto-create incident pages in Notion databases.
- [x] Implement **Slack Webhook** (`backend/notifiers/slack.py`) and **Generic JSON Webhook** (`backend/notifiers/generic_webhook.py`).
- [x] Implement `NotificationManager` dispatcher and CLI commands (`harvester history`, `harvester show`, `harvester test-notify`, `harvester test-notion`).

### Phase 4: Unified Config & CloudNativePG Storage
- [x] **Unified YAML Configuration (`config.yaml`)**:
  - Connection endpoints, DB, credentials, sinks, and sources configured in `config.yaml`.
  - Supports `${ENV_VAR}` and `${ENV_VAR:-default}` dynamic environment variable expansion.
- [x] **GUI Source Management & YAML Export**:
  - Add, toggle ON/OFF, and delete threat sources (RSS, Telegram, Darkweb, X, Web search) directly from GUI.
  - One-click "Export config.yaml" download feature.
- [x] **Multi-Database Support (PostgreSQL / CloudNativePG & SQLite)**:
  - SQLAlchemy-backed storage layer supporting PostgreSQL (CNPG on k3s) and SQLite fallback.
  - Dialect-aware upserts (`pg_insert` and `sqlite_insert`).
- [x] **Kubernetes / Helm Enhancements**:
  - Added CloudNativePG (`Cluster` CRD) integration and secret binding.

### Phase 5: Decoupled Full-Stack Architecture, Next.js SOC Dashboard & Go Backend
- [x] **Service Decoupling (`backend/` & `web/`)**:
  - Renamed and organized modules symmetrically into `backend/` and `web/`.
  - Removed awkward legacy folder structure.
- [x] **High-Performance Go CTI Engine (`backend/`)**:
  - Rebuilt backend in Go 1.22 with single static binary (`bin/information-harvester`, 25MB).
  - Parallel concurrent harvesting using Goroutines across RSS, Dark Web (.onion via Tor SOCKS5), Telegram, X, and Gemini Grounded Search.
  - Pure Go SQLite (`modernc.org/sqlite`, zero CGO) and PostgreSQL (CNPG) dual-engine support.
  - Chi-based lightweight, high-throughput REST API with full CORS support.
  - Multi-stage minimal Dockerfile (~25MB Alpine runner image).
- [x] **Docker Compose (`docker-compose.yml`)**:
  - Complete multi-container orchestration for `web` (Next.js), `backend` (Go CTI Engine), `db` (Postgres 16), and `tor` (Tor SOCKS5 proxy).
- [x] **Next.js 14 Cyber SOC Web Dashboard (`web/`)**:
  - Pure English user interface.
  - Reactive incident feeds, real-time filtering, detailed intelligence modal.
  - GUI threat intelligence source management with toggle, add, and delete.
  - Live YAML preview and downloadable `config.yaml`.
  - System health probes and test dispatch triggers.

### Phase 6: Cluster Deployment & Live Verification (Next Steps)
- [ ] Run `docker compose up -d` to verify local multi-container stack.
- [ ] Deploy Helm chart onto k3s cluster with CloudNativePG PostgreSQL.
- [ ] Verify Web Dashboard UI access and Tor SOCKS5 proxy connectivity in live cluster.

---

## Action Items (Prioritized Backlog)

### [P0] Immediate Next Steps
1. **Docker Compose Verification**:
   - Run `docker compose up -d --build` to confirm all 4 containers boot up and communicate cleanly.
2. **Cluster Deployment on k3s**:
   - Deploy Helm chart (`helm upgrade --install`) referencing CloudNativePG cluster.

### [P1] Live Source Validation
1. Verify Gemini Grounded Search response with live API key.
2. Verify Tor proxy routing against live .onion endpoints.
3. Test Telegram and RSS collection in production environment.
