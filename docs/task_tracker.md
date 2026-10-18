# Task Tracker - Threat Harvester

## Overview
Status tracking and milestone roadmap for the **Threat Harvester** project.

---

## Current Status
- **Current Version**: `v0.1.0`
- **Current Phase**: Phase 7 Completed / Planning Phase 8 (Strict Security Hardening & CSP)
- **Last Updated**: 2026-10-18

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

### Phase 7: Comprehensive Unit & E2E Testing Suite
- [x] **Repository Synchronization & Refactoring**:
  - Merged latest container separation architecture (`api/`, `worker/`, `web/`) from `develop`.
  - Removed deprecated legacy `backend/` and `tests/` directories.
- [x] **API (`api/`) Testing & Coverage**:
  - Built mock transport layer for Gemini and OpenAI-compatible threat analyzers (analyzing, batching, translations).
  - Unit tests covering REST API endpoints, incident clustering, groundings, and storage queries.
  - End-to-End integration test (`api/e2e_test.go`) validating end-to-end flow from RSS ingest to API delivery.
  - Achieved **75.1%** statement test coverage across the API service.
- [x] **Worker (`worker/`) Python Testing**:
  - Built pytest suite for Python harvesters, notifiers, models, and analyzers (24/24 passing, 72% coverage).
- [x] **Web (`web/`) Node.js Testing**:
  - Built unit tests for Next.js path resolution and basePath routing (6/6 passing).

### Phase 8: Strict Security Hardening & CSP Implementation (Scheduled: Next Week)
- [ ] **Strict Content Security Policy (CSP) Implementation (`web/`)**:
  - Configure strict CSP in `web/next.config.mjs` (or custom server / middleware):
    - Strict `script-src` and `style-src` (evaluate nonce / strict-dynamic vs hash-based enforcement for Next.js and Tailwind CSS; minimize or eliminate unsafe directives).
    - Restrict `default-src 'self'`, `connect-src 'self'`, `img-src 'self' data:`, `font-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`.
  - Add baseline defense-in-depth headers:
    - `Cross-Origin-Opener-Policy: same-origin`
    - `Cross-Origin-Resource-Policy: same-origin`
    - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
- [ ] **Subpath & Reverse-Proxy Compatibility Verification**:
  - Verify that strict CSP operates cleanly under `/threat` subpath prefix behind Traefik and CloudFront.
  - Test bilingual language toggling (`/en`, `/ja`), STIX 2.1 bundle export, RSS feeds (`/rss`), and dark mode theme switching without CSP console violations.
- [ ] **Automated Security Scan Verification**:
  - Validate against OWASP ZAP baseline scan rules to ensure zero alert regressions.

