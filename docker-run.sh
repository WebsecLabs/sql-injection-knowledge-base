#!/bin/bash
# Script to run sqli-kb container with proper network configuration

set -e

# Stop and remove existing containers
docker stop websec-sqli-kb sqli-kb 2>/dev/null || true
docker rm websec-sqli-kb sqli-kb 2>/dev/null || true

# Build the image
echo "Building sqli-kb image..."
if ! docker build -t sqli-kb .; then
  echo "Error: Failed to build sqli-kb image" >&2
  exit 1
fi

# Run container on the websec network so the proxy can reach it
docker run -d --name sqli-kb --network websec-site_websec-network -p 8080:80 sqli-kb

echo "Container started on websec-site_websec-network"
echo "  - sqli-kb: http://localhost:8080 (proxy: http://localhost/sql-injection-knowledge-base)"
