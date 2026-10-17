# Contributing to Threat Information Harvester

We welcome contributions from the open-source community! Whether you are reporting bugs, proposing new threat intelligence sources, improving AI analysis prompts, or optimizing Kubernetes Helm charts, your help is appreciated.

---

## 1. Development Environment

You can run the full stack locally using Docker Compose:

```bash
# 1. Copy example environment variables
cp .env.example .env

# 2. Build and start the services (Web Dashboard, Go Backend, PostgreSQL)
docker compose up -d --build
```

Or build and work with the Go backend and Next.js frontend directly:

```bash
# Backend (Go 1.22+)
cd backend
go mod download
go test -v ./...

# Web Dashboard (Node.js 20+)
cd ../web
npm ci
npm run dev
```

---

## 2. Coding Standards & Quality Checks

Before submitting a Pull Request, please ensure all tests, builds, and chart lints pass:

```bash
# 1. Run Go backend tests
cd backend && go test -v ./...

# 2. Verify Next.js production build & TypeScript checks
npm --prefix web run build

# 3. Lint Kubernetes Helm chart
helm lint charts/threat-harvester
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
- **Scope**: Module name (e.g., `backend`, `web`, `harvester`, `analyzer`, `helm`, `ci`)
- **Signature**: Sign all commits with a GPG/SSH key (`git commit -S` or `commit.gpgsign=true`). Verified signatures are required.

**Example:**
```text
feat(harvester): add new ransomware leak tracker source

- Add RansomFeed RSS feed integration
- Update onion proxy handler with retry logic
- Add unit tests for new source
```

---

## 4. Pull Request Process

1. Fork the repository and create your feature branch from `develop` or `main` (e.g., `feat/add-new-source`).
2. Implement your changes with accompanying unit tests.
3. Verify that all Go tests (`go test ./...`) and Next.js builds (`npm --prefix web run build`) pass.
4. Commit your changes using signed Conventional Commits (`git commit -S`).
5. Push to your fork and submit a Pull Request with a clear description of the modifications.
