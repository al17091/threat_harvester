# Task Tracker - Threat Information Harvester

## Overview
Status tracking for the **Threat Information Harvester** project. This file is referenced whenever planning or proposing the next actions.

---

## Current Status
- **Current Phase**: Phase 4 Completed / Ready for Cluster Deployment (k3s + CNPG)
- **Last Updated**: 2026-10-04

---

## Milestone Roadmap

### Phase 1: Foundation & Architecture Setup
- [x] Establish `AGENT.md` specifications, Git conventions, and interaction guidelines.
- [x] Initialize Git repository with proper conventions.
- [x] Create project task tracker (`docs/task_tracker.md`).
- [x] Refactor codebase structure into modular `src/` hierarchy (Harvesters, Analyzer, Notifiers, Storage, CLI).
- [x] Implement Unified CLI (`src/cli.py` and `bin/harvester`) for centralized command execution.
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
- [x] Implement **Notion Reporter** (`src/reporters/notion_reporter.py`) to auto-create incident pages in Notion databases.
- [x] Implement **Slack Webhook** (`src/notifiers/slack.py`) and **Generic JSON Webhook** (`src/notifiers/generic_webhook.py`).
- [x] Implement `NotificationManager` dispatcher and CLI commands (`harvester history`, `harvester show`, `harvester test-notify`, `harvester test-notion`).
- [x] Clean up legacy `.devcontainer` configuration.

### Phase 4: High-Performance Web Dashboard & CNPG Database Support
- [x] **High-Performance Web Dashboard (FastAPI + Tailwind/Alpine.js)**:
  - Cyber Threat Intelligence Dark Theme (SOC GUI).
  - Incidents timeline with real-time filtering (Severity, Japan Relevance, Source Type, Search).
  - Detailed incident modal displaying AI analysis, impact, victim orgs, actors, and recommended countermeasures.
  - On-demand "Run Harvest Now" asynchronous pipeline trigger with live status updates.
- [x] **Unified YAML Configuration (`config.yaml`)**:
  - All connection endpoints, DB, credentials, sinks, and sources configured in `config.yaml`.
  - Supports `${ENV_VAR}` and `${ENV_VAR:-default}` dynamic environment variable expansion.
- [x] **GUI Source Management & YAML Export**:
  - Add, toggle ON/OFF, and delete threat sources (RSS, Telegram, Darkweb, X, Web search) directly from GUI.
  - One-click "Export config.yaml" download feature.
- [x] **Multi-Database Support (PostgreSQL / CloudNativePG & SQLite)**:
  - SQLAlchemy-backed storage layer supporting PostgreSQL (CNPG on k3s) and SQLite fallback.
  - Dialect-aware upserts (`pg_insert` and `sqlite_insert`).
- [x] **Kubernetes / Helm Enhancements**:
  - Added Web Dashboard Deployment & Service (`port: 8080`) with Ingress support.
  - Added CloudNativePG (`Cluster` CRD) integration and secret binding.

### Phase 5: Cluster Deployment & Live Verification (Next Steps)
- [ ] Deploy Helm chart onto k3s cluster with CloudNativePG PostgreSQL.
- [ ] Verify Web Dashboard UI access via Service / Ingress on port 8080.
- [ ] Verify in-cluster Tor SOCKS5 proxy connectivity with `.onion` targets.
- [ ] Verify automated CronJob execution and log output.

---

## Action Items (Prioritized Backlog)

### [P0] Immediate Next Steps
1. **Cluster Deployment on k3s**:
   - Apply CloudNativePG cluster operator or deploy via Helm chart (`helm upgrade --install`).
   - Validate PostgreSQL connectivity and migration.
2. **Dashboard UI Verification**:
   - Access dashboard at `http://<node-ip>:8080` or via Ingress.
   - Test source toggling and YAML export in live cluster.

### [P1] Live Source Validation
1. Verify Gemini Grounded Search response with live API key.
2. Verify Tor proxy routing against live .onion endpoints.
3. Test Telegram and RSS collection in production environment.
