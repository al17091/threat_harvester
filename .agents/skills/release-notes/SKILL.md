---
name: release-notes
description: >-
  Standard operating procedure and canonical template for drafting, formatting,
  and publishing GitHub Releases across Threat Harvester and lab repositories.
---

# GitHub Release Notes Standard & Runbook

This skill defines the standardized workflow, markdown structure, and execution commands for drafting, reviewing, and publishing GitHub Releases in `threat_harvester` (and other lab repositories).

---

## 1. Core Principles & Formatting Rules

### 1.1 Release Title Invariant
> [!IMPORTANT]
> **The Release Title must strictly match the semantic tag format: `v<MAJOR>.<MINOR>.<PATCH>[-<PRERELEASE>]`.**  
> Example: `v0.2.0` (Do **NOT** prefix with project names like `Threat Harvester v0.2.0`).

### 1.2 Structure & Section Requirements
The release notes body must adhere to the following clean structure:

1. **Top Heading**:
   - Always `# What's Changed` (exact string, do not append version numbers or diff summaries to the title).
2. **Executive Summary**:
   - A concise 1–2 sentence summary explaining the primary purpose and scope of the release.
3. **Key Highlights & Categorized Changes**:
   - Group changes logically under `## 🚀 Key Highlights & New Features` (or relevant category headers).
   - Use numbered sub-headings (`### 1. ...`, `### 2. ...`) for major technical areas (e.g., Architecture, Caching/Performance, Storage/SQL, Dashboard/UI, Notifiers, Engineering Standards).
   - Provide clear, bulleted technical explanations highlighting performance metrics (e.g., payload reduction, latency drops) and architectural changes.
4. **Container Artifacts Table**:
   - Include a `## 📦 Container Images (GHCR)` section with a clean markdown table listing each service and its corresponding image tag.
5. **Full Commit Log / Comparison**:
   - Always conclude with `## 📋 Full Commit Log (<previous_tag> -> <current_tag>)`.
   - **Do NOT dump individual raw git commit lines.** Place solely the GitHub comparison URL on its own line:
     `https://github.com/al17091/<repo>/compare/<previous_tag>...<current_tag>`

---

## 2. Canonical Markdown Template

```markdown
# What's Changed

[Concise 1-2 sentence executive summary of the release.]

---

## 🚀 Key Highlights & New Features

### 1. [Major Feature / Architectural Shift]
- **[Component Name (`path/`)]**: Description of the changes and technical mechanisms.
- **[Protocol / Standard]**: Key protocols or standards implemented.

### 2. [Performance & Optimizations]
- **[Tier / Area]**: Concrete optimization details, benchmarks, or metrics (e.g., payload reduction, cache behavior).

### 3. [Bug Fixes & Refinements]
- **[Component]**: Description of resolved bug and root cause fix.

### 4. [Documentation & Engineering Standards]
- Updates to runbooks, policies, or architecture documentation.

---

## 📦 Container Images (GHCR)

| Service | Image Tag |
| :--- | :--- |
| **API Engine** | `ghcr.io/al17091/<repo>:api-<version>` |
| **Autonomous Agent** | `ghcr.io/al17091/<repo>:agent-<version>` |
| **Ingestion Worker** | `ghcr.io/al17091/<repo>:worker-<version>` |
| **SOC Dashboard** | `ghcr.io/al17091/<repo>:web-<version>` |
| **Unified Backend** | `ghcr.io/al17091/<repo>:backend-<version>` |

---

## 📋 Full Commit Log (<previous_version> -> <current_version>)

https://github.com/al17091/<repo>/compare/<previous_version>...<current_version>
```

---

## 3. Publication Workflow

### Step 1: Verify Tag & Identify Previous Version
Identify the current release tag and the preceding tag to construct the comparison URL:
```bash
git describe --tags --abbrev=0 HEAD
# Find previous tag:
git tag --sort=-creatordate | head -n 5
```

### Step 2: Publish via GitHub CLI (`gh`)
The GitHub CLI (`gh`) is authenticated inside the workspace container (`lab-infra-workspace-1`). Draft the notes locally and pipe directly into `gh release`:

```bash
# To create a new release:
cat << 'EOF' | docker exec -i lab-infra-workspace-1 gh release create <version_tag> \
  --repo al17091/<repo> \
  --title "<version_tag>" \
  --notes-file -
[Release Notes Markdown Content]
EOF

# To update an existing release:
cat << 'EOF' | docker exec -i lab-infra-workspace-1 gh release edit <version_tag> \
  --repo al17091/<repo> \
  --title "<version_tag>" \
  --notes-file -
[Release Notes Markdown Content]
EOF
```

### Step 3: Verify Output
Verify that the published release matches the canonical format:
```bash
docker exec lab-infra-workspace-1 gh release view <version_tag> --repo al17091/<repo>
```
