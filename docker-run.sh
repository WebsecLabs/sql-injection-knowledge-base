#!/bin/bash
# Script to run sqli-kb container with proper network configuration
#
# Environment variables:
#   SQLI_KB_NETWORK - Docker network to join (default: websec-site_websec-network)

set -e

# Stop and remove existing containers
docker stop sqli-kb 2>/dev/null || true
docker rm sqli-kb 2>/dev/null || true

# Network configuration (override with SQLI_KB_NETWORK env var)
NETWORK="${SQLI_KB_NETWORK:-websec-site_websec-network}"

# Check if network exists and set mode-specific variables
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  MODE="integrated"
  DOCKER_RUN_ARGS=(--network "$NETWORK")
  echo "Building sqli-kb image (integrated mode)..."
else
  MODE="standalone"
  DOCKER_RUN_ARGS=()
  echo "Building sqli-kb image (standalone mode)..."
fi

# Build the application
if [ "$MODE" = "integrated" ]; then
  if ! npm run build; then
    echo "Error: Failed to build application (integrated mode)" >&2
    exit 1
  fi
else
  if ! STANDALONE=true npm run build; then
    echo "Error: Failed to build application (standalone mode)" >&2
    exit 1
  fi
fi

# Build Docker image
if ! docker build -t sqli-kb .; then
  echo "Error: Failed to build sqli-kb image" >&2
  exit 1
fi

# Run container with mode-specific arguments
if ! docker run -d --name sqli-kb "${DOCKER_RUN_ARGS[@]}" -p 8080:80 sqli-kb; then
  echo "Error: Failed to start sqli-kb container" >&2
  exit 1
fi

# Output mode-specific message
if [ "$MODE" = "integrated" ]; then
  echo "Container started on $NETWORK"
  echo "  - sqli-kb: http://localhost:8080 (proxy: http://localhost/sql-injection-knowledge-base)"
else
  echo "Container started (standalone mode)"
  echo "  - sqli-kb: http://localhost:8080/"
fi
