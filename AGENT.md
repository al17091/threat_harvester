# AGENT.md - AI Agent & Developer Guidelines

Guidelines, constraints, and operational protocols for AI coding assistants and contributors working on **Threat Information Harvester**.

---

## 1. Core Principles & Constraints

1. **Permissive Open Source (MIT)**:
   - Code must remain fully compatible with the MIT License (commercial and non-commercial use allowed).
   - Only dependencies with permissive open-source licenses (MIT, Apache 2.0, BSD) are allowed. Avoid copyleft licenses (e.g., AGPL/GPL).
2. **Container Image Naming**:
   - The Docker image name is strictly `information_harvester` (underscored, e.g., `ghcr.io/dapt/information_harvester`). Never use `threat-harvester` or other aliases.
3. **Database & Architecture Target**:
   - Deployment target is k3s with PostgreSQL provided by CloudNativePG (CNPG), falling back to SQLite for local development.
   - All database operations in `src/storage/` must remain dialect-aware (PostgreSQL + SQLite) via SQLAlchemy.
4. **Security & Secrets**:
   - Never commit hardcoded tokens, API keys, passwords, or webhook URLs.
   - Configuration must load from `config.yaml` with dynamic `${ENV_VAR}` expansion or direct environment variables.

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
- The user's SSH signing key (`git@engineerlab.jp`) is configured in the environment (`commit.gpgsign=true`).
- **Never** use `--no-gpg-sign` or bypass commit signing.

---

## 3. Interaction & Task Tracking Protocol

- **Next Steps Inquiries**: When the user asks "What should we do next?" (「次は何をすればいい？」), consult [`docs/task_tracker.md`](docs/task_tracker.md), evaluate priorities, and propose concrete, prioritized actions in Japanese.
- **Task Tracking Updates**: Keep [`docs/task_tracker.md`](docs/task_tracker.md) synchronized when completing milestones or establishing new backlog items.

---

## 4. Code & Quality Standards

1. **Language & Environment**:
   - Python 3.11+ using the local virtual environment (`.venv/bin/python`, `.venv/bin/pytest`).
2. **Type Annotations**:
   - All new functions, methods, and data structures must have complete type annotations.
3. **Quality Gates**:
   - **Linter**: `ruff check .` must pass with zero errors.
   - **Tests**: `pytest tests/` must pass completely before concluding any task.
   - **Helm Lint**: `helm lint charts/information-harvester` must report 0 failures when chart manifests are modified.
4. **Resilience & Fault Tolerance**:
   - Threat collectors (`src/harvesters/`) must never crash the pipeline on external timeouts or HTTP errors. Handle exceptions gracefully with informative logging.
   - Sinks (`src/notifiers/`, `src/reporters/`) must fail safely without interrupting data collection.
