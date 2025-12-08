#!/bin/bash
# Script to run sqli-kb container with proper network configuration

set -e

# Stop and remove existing containers
docker stop sqli-kb 2>/dev/null || true
docker rm sqli-kb 2>/dev/null || true

# Build the image
echo "Building sqli-kb image..."
if ! docker build -t sqli-kb .; then
  echo "Error: Failed to build sqli-kb image" >&2
  exit 1
fi

# Check if websec network exists and join it if available
NETWORK="websec-site_websec-network"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  docker run -d --name sqli-kb --network "$NETWORK" -p 8080:80 sqli-kb
  echo "Container started on $NETWORK"
  echo "  - sqli-kb: http://localhost:8080 (proxy: http://localhost/sql-injection-knowledge-base)"
else
  docker run -d --name sqli-kb -p 8080:80 sqli-kb
  echo "Container started (standalone mode)"
  echo "  - sqli-kb: http://localhost:8080/sql-injection-knowledge-base/"
fi
