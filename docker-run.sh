#!/bin/bash
# Script to run sqli-kb container with proper network configuration

set -e

# Stop and remove existing containers
docker stop sqli-kb 2>/dev/null || true
docker rm sqli-kb 2>/dev/null || true

# Check if websec network exists
NETWORK="websec-site_websec-network"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  # Integrated mode - build with base path for websec.ca
  echo "Building sqli-kb image (integrated mode)..."
  npm run build
  if ! docker build -t sqli-kb .; then
    echo "Error: Failed to build sqli-kb image" >&2
    exit 1
  fi
  docker run -d --name sqli-kb --network "$NETWORK" -p 8080:80 sqli-kb
  echo "Container started on $NETWORK"
  echo "  - sqli-kb: http://localhost:8080 (proxy: http://localhost/sql-injection-knowledge-base)"
else
  # Standalone mode - build with root base path
  echo "Building sqli-kb image (standalone mode)..."
  STANDALONE=true npm run build
  if ! docker build -t sqli-kb .; then
    echo "Error: Failed to build sqli-kb image" >&2
    exit 1
  fi
  docker run -d --name sqli-kb -p 8080:80 sqli-kb
  echo "Container started (standalone mode)"
  echo "  - sqli-kb: http://localhost:8080/"
fi
