# Task Tracker - Threat Information Harvester

## Overview
Status tracking for the **Threat Information Harvester** project. This file is referenced whenever planning or proposing the next actions.

---

## Current Status
- **Current Phase**: Phase 1: Foundation & Architecture Setup
- **Last Updated**: 2026-10-04

---

## Milestone Roadmap

### Phase 1: Foundation & Architecture Setup (Current)
- [x] Establish `AGENT.md` specifications, Git conventions, and interaction guidelines.
- [x] Initialize Git repository with proper conventions.
- [x] Create project task tracker (`docs/task_tracker.md`).
- [ ] Refactor codebase structure into modular `src/` hierarchy (Harvesters, Analyzer, Notifiers, Storage, CLI).
- [ ] Implement Unified CLI (`src/cli.py`) for centralized command execution.
- [ ] Create development container configuration (`Dockerfile.dev` and devcontainer configs).
- [ ] Initialize Helm Chart structure (`charts/information-harvester/`) with Tor proxy and Dev Pod support.

### Phase 2: Core Harvesters Implementation (Low-Cost / High-Value Focus)
- [ ] **Vendor & CERT RSS Harvester**:
  - Add Japanese feeds (JPCERT/CC, IPA, ScanNetSecurity, Security Next).
  - Retain & improve global feeds (BleepingComputer, The Hacker News, CISA).
- [ ] **Gemini Web Search Grounding Harvester**:
  - Implement query-based threat hunting using Gemini Search Grounding for Japan-focused breaches/ransomware.
- [ ] **Dark Web (.onion) Harvester via Tor**:
  - Integrate SOCKS5 proxy connectivity (`requests[socks]`).
  - Implement scraper for ransomware leak sites and public aggregator feeds.
- [ ] **Telegram Monitor Harvester**:
  - Implement public channel web-preview scraper (`t.me/s/<channel>`) without requiring API credentials.
  - Add support for Telethon / Bot API when credentials are provided.
- [ ] **X (Twitter) Monitor Harvester**:
  - Implement low-cost monitoring (Gemini Grounded X query / Nitter / RSS bridge).

### Phase 3: Gemini Analysis Pipeline & Japan Targeting
- [ ] Enhance Gemini analysis prompt with structured schema:
  - Severity: `Critical` | `High` | `Medium` | `Low`
  - Japan Target Relevance: `Direct` (Japanese org attacked) | `Indirect` (Global attack affecting Japan) | `None`
  - Threat Actor, Victim Name, Industry Sector
  - Japanese Summary & Actionable Recommendations
- [ ] Implement persistent deduplication cache (SQLite/JSON on PVC) to prevent duplicate notifications.
- [ ] Enhance Discord alerts with rich color-coded embeds and Japan-target highlight flags.

### Phase 4: Kubernetes Helm Chart & Dev Container Deployment
- [ ] Create Helm Chart with configurable values:
  - Harvester CronJob / Daemon
  - Tor SOCKS5 Proxy Pod & Service
  - PersistentVolumeClaim for dedup cache
  - Dev/Admin Pod for running `harvester` CLI in the cluster
- [ ] Test deployment on the local Kubernetes cluster (`k3s`).
- [ ] Verify manual test commands from inside the dev container.

### Phase 5: Verification & End-to-End Testing
- [ ] Test Tor SOCKS5 connectivity against live `.onion` mirrors/aggregators.
- [ ] Run test harvests on all 5 sources and verify Gemini enrichment.
- [ ] Perform Discord alert dispatch verification.
- [ ] Write user guide and update `README.md`.

---

## Action Items (Prioritized Backlog)

### [P0] Critical Foundation
1. **Directory Structure Refactoring**:
   - Create `src/`, `src/harvesters/`, `src/analyzer/`, `src/storage/`, `src/notifiers/`.
   - Update `requirements.txt` with PySocks, pydantic, click/rich, etc.
2. **Unified CLI Implementation**:
   - Provide `harvester` CLI entrypoint for testing, running, and status checking.
3. **Dev Container & Helm Chart**:
   - Build `Dockerfile.dev` and Helm templates for the dev pod, Tor proxy, and harvester.

### [P1] Data Collection Modules
1. Expand RSS feeds to include JPCERT/CC and IPA.
2. Build Gemini Grounded Web Search harvester for Japan-targeted threats.
3. Build Tor-based .onion harvester with resilient timeouts.
4. Implement Telegram public channel collector.
5. Implement X monitor collector.

### [P2] Refinements & Enhancements
1. Add SQLite-based historic log and query command in CLI.
2. Add optional Slack or Webhook targets.
3. Integrate SearXNG internal search engine if configured in cluster.
