# Contributing to Threat Information Harvester

We welcome contributions from the open-source community! Whether you are reporting bugs, proposing new threat intelligence sources, improving Gemini prompts, or optimizing Kubernetes Helm charts, your help is appreciated.

---

## 1. Development Environment

The fastest way to start contributing is using the provided development container:

```bash
# Build the dev container
docker build -t threat-harvester:dev -f Dockerfile.dev .

# Run dev shell
docker run -it --rm -v $(pwd):/app threat-harvester:dev bash
```

Or using a local virtual environment (Python 3.11+):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

---

## 2. Coding Standards & Quality Checks

Before submitting a Pull Request, please ensure all checks pass:

```bash
# Run automated tests
pytest tests/

# Run linter and formatting checks
ruff check .
ruff format --check .
```

---

## 3. Git Commit Conventions

All Git commit messages MUST follow the **Conventional Commits** format in English:

```text
<type>(<scope>): <subject>

- <description item 1>
- <description item 2>
```

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`
- **Scope**: Module name (e.g., `harvester`, `analyzer`, `helm`, `cli`, `cache`)
- **Signature**: Please use `--no-gpg-sign` during development commits unless instructed otherwise.

**Example:**
```text
feat(harvester): add new ransomware leak tracker source

- Add RansomFeed RSS feed integration
- Update onion proxy handler with retry logic
- Add unit tests for new source in tests/
```

---

## 4. Pull Request Process

1. Fork the repository and create your branch from `main` (e.g. `feature/add-new-source`).
2. Implement your changes with accompanying unit tests in `tests/`.
3. Verify that all tests pass (`pytest`) and code style complies (`ruff check`).
4. Commit your changes following the commit conventions above.
5. Push to your fork and submit a Pull Request with a clear description of the modifications.
