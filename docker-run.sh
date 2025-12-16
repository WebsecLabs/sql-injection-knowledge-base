#!/bin/bash
# Script to run sqli-kb container with proper network configuration

set -e

# Stop and remove existing containers
docker stop sqli-kb 2>/dev/null || true
docker rm sqli-kb 2>/dev/null || true

# Check if websec network exists and set mode-specific variables
NETWORK="websec-site_websec-network"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  MODE="integrated"
  BUILD_CMD="npm run build"
  DOCKER_RUN_ARGS="--network $NETWORK"
  echo "Building sqli-kb image (integrated mode)..."
else
  MODE="standalone"
  BUILD_CMD="STANDALONE=true npm run build"
  DOCKER_RUN_ARGS=""
  echo "Building sqli-kb image (standalone mode)..."
fi

# Build the application
eval "$BUILD_CMD"

# Build Docker image
if ! docker build -t sqli-kb .; then
  echo "Error: Failed to build sqli-kb image" >&2
  exit 1
fi

# Run container with mode-specific arguments
docker run -d --name sqli-kb $DOCKER_RUN_ARGS -p 8080:80 sqli-kb

# Output mode-specific message
if [ "$MODE" = "integrated" ]; then
  echo "Container started on $NETWORK"
  echo "  - sqli-kb: http://localhost:8080 (proxy: http://localhost/sql-injection-knowledge-base)"
else
  echo "Container started (standalone mode)"
  echo "  - sqli-kb: http://localhost:8080/"
fi
