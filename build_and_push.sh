#!/usr/bin/env bash
set -e

# Configuration
IMAGE_NAME="security-watchdog"
IMAGE_TAG="latest"

if [ -z "$1" ]; then
    echo "Usage: ./build_and_push.sh <github-username>"
    echo "Example: ./build_and_push.sh al17091"
    exit 1
fi

GH_USERNAME=$(echo "$1" | tr '[:upper:]' '[:lower:]')
GHCR_REPO="ghcr.io/${GH_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"

echo "Building Docker image..."
docker build -t ${GHCR_REPO} .

echo "Pushing image to ${GHCR_REPO}..."
docker push ${GHCR_REPO}

echo "Successfully built and pushed ${GHCR_REPO}"
