#!/usr/bin/env bash
set -e

# Configuration
IMAGE_NAME="information_harvester"
IMAGE_TAG="${2:-latest}"

if [ -z "$1" ]; then
    echo "Usage: ./build_and_push.sh <github-username> [image-tag] [dockerfile]"
    echo "Example: ./build_and_push.sh al17091 latest"
    echo "Example (dev): ./build_and_push.sh al17091 dev Dockerfile.dev"
    exit 1
fi

GH_USERNAME=$(echo "$1" | tr '[:upper:]' '[:lower:]')
GHCR_REPO="ghcr.io/${GH_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
DOCKERFILE="${3:-Dockerfile}"

echo "Building Docker image ${GHCR_REPO} from ${DOCKERFILE}..."
docker build -t ${GHCR_REPO} -f ${DOCKERFILE} .

echo "Pushing image to ${GHCR_REPO}..."
docker push ${GHCR_REPO}

echo "Successfully built and pushed ${GHCR_REPO}"
