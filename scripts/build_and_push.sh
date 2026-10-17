#!/usr/bin/env bash
set -e

# Configuration
IMAGE_NAME="information_harvester"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: ./scripts/build_and_push.sh <github-username> [version] [all|backend|web|dev]"
    echo "Examples:"
    echo "  ./scripts/build_and_push.sh al17091                  # Uses VERSION file (e.g. 0.1.0, or 0.1.0-preview on develop branch)"
    echo "  ./scripts/build_and_push.sh al17091 0.1.0 all        # Build & push backend-0.1.0 and web-0.1.0"
    echo "  ./scripts/build_and_push.sh al17091 0.0.5-preview    # Build & push backend-0.0.5-preview and web-0.0.5-preview"
    echo "  ./scripts/build_and_push.sh al17091 0.1.0 backend    # Build & push backend-0.1.0 only"
    echo "  ./scripts/build_and_push.sh al17091 0.1.0 web        # Build & push web-0.1.0 only"
    echo "  ./scripts/build_and_push.sh al17091 0.1.0 dev        # Build & push dev-0.1.0 only"
    exit 1
fi

GH_USERNAME=$(echo "$1" | tr '[:upper:]' '[:lower:]')
BASE_REPO="ghcr.io/${GH_USERNAME}/${IMAGE_NAME}"

# Resolve version from 2nd arg or VERSION file
if [ -n "$2" ] && [[ "$2" != "all" && "$2" != "backend" && "$2" != "web" && "$2" != "dev" ]]; then
    VERSION="${2#v}"
    TARGET="${3:-all}"
else
    if [ -f "${ROOT_DIR}/VERSION" ]; then
        VERSION=$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")
    else
        VERSION="0.1.0"
    fi
    CURRENT_BRANCH=$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    if [ "${CURRENT_BRANCH}" = "develop" ] && [[ "${VERSION}" != *-preview ]]; then
        VERSION="${VERSION}-preview"
    fi
    TARGET="${2:-all}"
fi

build_and_push_backend() {
    local tag="backend-${VERSION}"
    echo "==> Building Backend image ${BASE_REPO}:${tag} from backend/Dockerfile..."
    docker build -t "${BASE_REPO}:${tag}" -f "${ROOT_DIR}/backend/Dockerfile" "${ROOT_DIR}"
    echo "==> Pushing ${BASE_REPO}:${tag}..."
    docker push "${BASE_REPO}:${tag}"
}

build_and_push_web() {
    local tag="web-${VERSION}"
    echo "==> Building Web Dashboard image ${BASE_REPO}:${tag} from web/Dockerfile..."
    docker build -t "${BASE_REPO}:${tag}" -f "${ROOT_DIR}/web/Dockerfile" "${ROOT_DIR}/web"
    echo "==> Pushing ${BASE_REPO}:${tag}..."
    docker push "${BASE_REPO}:${tag}"
}

build_and_push_dev() {
    local tag="dev-${VERSION}"
    echo "==> Building Dev CLI image ${BASE_REPO}:${tag} from Dockerfile.dev..."
    docker build -t "${BASE_REPO}:${tag}" -f "${ROOT_DIR}/Dockerfile.dev" "${ROOT_DIR}"
    echo "==> Pushing ${BASE_REPO}:${tag}..."
    docker push "${BASE_REPO}:${tag}"
}

case "${TARGET}" in
    all)
        build_and_push_backend
        build_and_push_web
        ;;
    backend)
        build_and_push_backend
        ;;
    web)
        build_and_push_web
        ;;
    dev)
        build_and_push_dev
        ;;
    *)
        echo "Unknown target '${TARGET}'. Supported targets: all, backend, web, dev"
        exit 1
        ;;
esac

echo "Successfully built and pushed '${TARGET}' (version: ${VERSION}) to ${BASE_REPO}"
