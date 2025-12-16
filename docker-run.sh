#!/bin/bash
# Script to run sqli-kb container with proper network configuration
#
# Environment variables:
#   SQLI_KB_NETWORK  - Docker network to join (default: websec-site_websec-network)
#   SQLI_KB_PORT     - Host port to expose (default: 8080)
#   SQLI_KB_SITE_URL - Site URL for standalone mode (default: http://localhost:$PORT)

set -e

# Change to script directory so relative paths work regardless of where script is invoked
cd "$(dirname "$0")"

# Configuration (override with environment variables)
NETWORK="${SQLI_KB_NETWORK:-websec-site_websec-network}"
PORT="${SQLI_KB_PORT:-8080}"

# Pre-flight checks
check_prerequisites() {
  local missing=()

  if ! command -v node >/dev/null 2>&1; then
    missing+=("node")
  fi

  if ! command -v npm >/dev/null 2>&1; then
    missing+=("npm")
  fi

  if ! command -v docker >/dev/null 2>&1; then
    missing+=("docker")
  fi

  if [ ${#missing[@]} -ne 0 ]; then
    echo "Error: Missing required tools: ${missing[*]}" >&2
    echo "Please install the missing dependencies and try again." >&2
    exit 1
  fi

  if [ ! -d "node_modules" ]; then
    echo "Error: node_modules directory not found." >&2
    echo "Please run 'npm install' first to install dependencies." >&2
    exit 1
  fi
}

check_prerequisites

# Stop and remove existing containers
docker stop sqli-kb 2>/dev/null || true
docker rm sqli-kb 2>/dev/null || true

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
# Note: STANDALONE and SITE_URL env vars are read by astro.config.mjs
if [ "$MODE" = "integrated" ]; then
  if ! npm run build; then
    echo "Error: Failed to build application (integrated mode)" >&2
    exit 1
  fi
else
  # Standalone mode requires SITE_URL for sitemap generation
  SITE_URL="${SQLI_KB_SITE_URL:-http://localhost:${PORT}}"
  if ! SITE_URL="$SITE_URL" npm run build:standalone; then
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
if ! docker run -d --name sqli-kb ${DOCKER_RUN_ARGS[@]+"${DOCKER_RUN_ARGS[@]}"} -p "${PORT}:80" sqli-kb; then
  echo "Error: Failed to start sqli-kb container" >&2
  exit 1
fi

# Output mode-specific message
if [ "$MODE" = "integrated" ]; then
  echo "Container started on $NETWORK"
  echo "  - sqli-kb: http://localhost:${PORT} (proxy: http://localhost/sql-injection-knowledge-base)"
else
  echo "Container started (standalone mode)"
  echo "  - sqli-kb: http://localhost:${PORT}/"
fi
