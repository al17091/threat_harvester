# AGENT.md - AI Agent & Developer Guidelines

Guidelines, constraints, and operational protocols for AI coding assistants and contributors working on **Threat Harvester**.

---

## 1. Core Principles & Constraints

1. **Permissive Open Source (MIT)**:
   - Code must remain fully compatible with the MIT License (commercial and non-commercial use allowed).
   - Only dependencies with permissive open-source licenses (MIT, Apache 2.0, BSD) are allowed. Avoid copyleft licenses (e.g., AGPL/GPL).
2. **Project Structure**:
   - `api/`: High-performance Go CTI Engine (`threat-harvester`), REST API, Hybrid AI analyzer, and concurrent threat harvesters.
   - `worker/`: Python Threat Harvester & Analysis Worker (extensible crawlers, batch runner, enrichment).
   - `web/`: Next.js 16 (TypeScript, Tailwind CSS, Lucide React) Cyber SOC Dashboard.
   - Orchestration via `docker-compose.yml` (development/testing) and Helm (`charts/threat-harvester/` for k3s).
3. **Container Image Naming**:
   - The Docker image repository is strictly `ghcr.io/al17091/threat_harvester` with separated microservice tags (`api-<version>`, `worker-<version>`, `agent-<version>`, and `web-<version>`). Legacy monolithic `backend-<version>` is deprecated and no longer built or deployed.
4. **Database & Architecture Target**:
   - Deployment target is k3s with PostgreSQL provided by CloudNativePG (CNPG), falling back to SQLite for local development.
   - All database operations in `api/internal/storage/` must remain dialect-aware (PostgreSQL + SQLite).
5. **Security & Secrets**:
   - Never commit hardcoded tokens, API keys, passwords, or webhook URLs.
   - Configuration must load from `config.yaml` with dynamic `${ENV_VAR}` expansion or direct environment variables.
6. **English-Only Repository Documentation**:
   - All repository documentation (`docs/`, `*.md`), code comments, commit messages, and PR descriptions must be written strictly in English.

---

## 2. Git Conventions & Mandatory Commit Signing

All commits **MUST** be signed and adhere to Conventional Commits in English:

### 2.1 Commit Message Format
```text
<type>(<scope>): <subject>

- <description item 1>
- <description item 2>
```
- **Line 1**: Imperative present-tense summary (`feat(...)`, `fix(...)`, `refactor(...)`, `docs(...)`, `test(...)`, `chore(...)`).
- **Line 2**: Blank line.
- **Line 3+**: Bulleted list of specific changes.

### 2.2 Mandatory Signature
- **Always sign commits**: `git commit -S -m "..."`.
- The user's SSH signing key is configured in the environment (`commit.gpgsign=true`).
- **Never** use `--no-gpg-sign` or bypass commit signing.

---

## 3. Interaction & Task Tracking Protocol

- **Next Steps Inquiries**: When the user asks "What should we do next?", consult [`docs/task_tracker.md`](docs/task_tracker.md), evaluate priorities, and propose concrete, prioritized actions.
- **Task Tracking Updates**: Keep [`docs/task_tracker.md`](docs/task_tracker.md) synchronized when completing milestones or establishing new backlog items.

---

## 4. Code & Quality Standards

1. **Language & Environment**:
   - Go 1.22+ for the backend CTI engine and REST API.
   - Node.js 20+ / Next.js for the `web/` dashboard.
2. **Quality Gates**:
   - **Go Tests**: `go test -v ./...` in `api/` must pass completely.
   - **Frontend Build**: `npm --prefix web run build` must compile cleanly without errors.
   - **Helm Lint**: `helm lint charts/threat-harvester` must report 0 failures when chart manifests are modified.
3. **Resilience & Fault Tolerance**:
   - Threat collectors (`api/internal/harvesters/`, `worker/harvesters/`) must never crash the pipeline on external timeouts or HTTP errors. Handle exceptions gracefully with informative logging.
   - Sinks (`api/internal/notifiers/`, `api/internal/reporters/`) must fail safely without interrupting data collection.

---

## 5. Performance & Caching Policy

Threat Harvester implements a multi-tier caching and rendering optimization architecture to maintain zero layout-shift, instantaneous page flips, and lightweight API payloads:
- Full specification: [`docs/caching_and_performance_policy.md`](docs/caching_and_performance_policy.md).
- **Tier 1 (Client Cache)**: Feed pagination is cached in-memory (`useRef<Map>`) with composite key `${lang}:${page}:${size}:${search}:${severity}:${japan}:${source}:${sort}`. Invalidate on filter changes, language switch, manual refresh, and harvest completion (`handleHarvestFinished`).
- **Tier 2 (Zero Layout Shift)**: Never display full-height skeleton/spinner over existing incident lists. Use top 2px pulse line + `opacity-60` fade.
- **Tier 3 (Projection Separation)**: Incident list queries (`incidentListSelectCols`) must NEVER load heavy TOAST columns (`raw_content`, `sources_detail`, `source_urls`). Reserve full projections for single-incident details (`/api/incidents/:id`).
- **Tier 4 (API Concurrency)**: Parallelize distinct queries (e.g. `GetIncidents` and `GetIncidentsTotal`) using Go `sync.WaitGroup`.

---

## 6. Agent Skills

Operational runbooks and SOP skills are maintained in `.agents/skills/`:
- **[`release-notes`](.agents/skills/release-notes/SKILL.md)**: Canonical formatting rules, section templates, and publication runbook for GitHub releases.

