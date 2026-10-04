# Task Tracker - Threat Information Harvester

## Overview
Status tracking for the **Threat Information Harvester** project. This file is referenced whenever planning or proposing the next actions.

---

## Current Status
- **Current Phase**: Phase 2: Live Verification & Testing on Cluster
- **Last Updated**: 2026-10-04

---

## Milestone Roadmap

### Phase 1: Foundation & Architecture Setup
- [x] Establish `AGENT.md` specifications, Git conventions, and interaction guidelines.
- [x] Initialize Git repository with proper conventions.
- [x] Create project task tracker (`docs/task_tracker.md`).
- [x] Refactor codebase structure into modular `src/` hierarchy (Harvesters, Analyzer, Notifiers, Storage, CLI).
- [x] Implement Unified CLI (`src/cli.py` and `bin/harvester`) for centralized command execution.
- [x] Create development container configuration (`Dockerfile.dev` and `.devcontainer/devcontainer.json`).
- [x] Initialize Helm Chart structure (`charts/information-harvester/`) with Tor proxy, CronJob, and Dev Pod support.

### Phase 2: Core Harvesters & Enrichment Implementation
- [x] **Vendor & CERT RSS Harvester**:
  - Added Japanese feeds (JPCERT/CC, IPA, ScanNetSecurity, Security Next).
  - Retained & improved global feeds (BleepingComputer, The Hacker News, CISA).
- [x] **Gemini Web Search Grounding Harvester**:
  - Implemented query-based threat hunting using Gemini Search Grounding for Japan-focused breaches/ransomware.
- [x] **Dark Web (.onion) Harvester via Tor**:
  - Integrated SOCKS5 proxy connectivity (`requests[socks]` / PySocks).
  - Implemented scraper for ransomware leak sites and public aggregator feeds.
- [x] **Telegram Monitor Harvester**:
  - Implemented public channel web-preview scraper (`t.me/s/<channel>`) without requiring API credentials.
- [x] **X (Twitter) Monitor Harvester**:
  - Implemented low-cost monitoring via Gemini Grounded search targeting X threat researcher handles.
- [x] **Gemini Intelligence Enrichment**:
  - Implemented structured schema: Severity (`Critical`/`High`/`Medium`/`Low`), Japan Target Relevance (`Direct`/`Indirect`/`None`), Victims, Threat Actors, and Japanese summaries.
- [x] **Persistent Cache & Notifications**:
  - SQLite persistent cache for deduplication.
  - Rich Discord notifications with Japan-target highlight flags.

### Phase 3: Cluster Testing & Dev Container Validation (Next Steps)
- [ ] Deploy Helm chart in test namespace or local k3s (`helm upgrade --install`).
- [ ] Exec into the `information-harvester-dev` Pod and run `harvester status`.
- [ ] Test in-cluster Tor SOCKS5 proxy connectivity with `.onion` targets.
- [ ] Verify automated CronJob execution and log output.

### Phase 4: Refinements & Documentation
- [ ] Add CLI command to inspect historical cached threats (`harvester history`).
- [ ] Provide optional Slack Webhook support alongside Discord.
- [ ] Integrate SearXNG internal search engine if configured in cluster.

---

## Action Items (Prioritized Backlog)

### [P0] Immediate Next Steps
1. **Cluster Deployment Verification**:
   - Deploy `information-harvester` Helm chart to a dedicated namespace (e.g. `cti` or `security`).
   - Verify that Tor Proxy Pod, Dev CLI Pod, and CronJob initialize cleanly.
2. **Dev Pod Operational Verification**:
   - Access `information-harvester-dev` Pod via `kubectl exec`.
   - Run `harvester status` and test individual sources.

### [P1] Live Source Validation
1. Verify Gemini Grounded Search response with live API key.
2. Verify Tor proxy routing against live .onion endpoints.
3. Test Telegram and RSS collection in production environment.

### [P2] Extensibility & Analytics
1. Implement Prometheus metrics or health exporter if needed.
2. Support configurable alerting thresholds per Discord channel.
