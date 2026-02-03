#!/bin/bash
# Docker build script for SentinelFlow

set -e

VERSION=${1:-dev}
PLATFORMS=${2:-linux/amd64,linux/arm64}
PUSH=${3:-false}

echo "Building SentinelFlow Docker image..."
echo "Version: $VERSION"
echo "Platforms: $PLATFORMS"

# Build multi-platform image
if [ "$PUSH" = "true" ]; then
    docker buildx build \
        --platform "$PLATFORMS" \
        --build-arg VERSION="$VERSION" \
        -t "sentinelflow/sentinelflow:$VERSION" \
        -t "sentinelflow/sentinelflow:latest" \
        --push \
        .
else
    docker buildx build \
        --platform "$PLATFORMS" \
        --build-arg VERSION="$VERSION" \
        -t "sentinelflow/sentinelflow:$VERSION" \
        -t "sentinelflow/sentinelflow:latest" \
        --load \
        .
fi

echo "Docker image built successfully!"

# Print image size
docker images sentinelflow/sentinelflow:latest --format "Size: {{.Size}}"
