#!/usr/bin/env bash
# Start FastMCP EDB96 server in Docker
set -e

BUILD=false
DETACHED="-d"
COMPOSE_FILE="docker/docker-compose.yml"

while [[ $# -gt 0 ]]; do
    case $1 in
        --build) BUILD=true; shift ;;
        --no-detach) DETACHED=""; shift ;;
        --prod) COMPOSE_FILE="docker/docker-compose.runtime.yml"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate .env exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found. Copy .env.example to .env and configure credentials."
    exit 1
fi

echo "Starting FastMCP EDB96 Dual-Instance Server..."

if [ "$BUILD" = true ]; then
    echo "Building Docker image..."
    docker compose -f "$COMPOSE_FILE" build
fi

docker compose -f "$COMPOSE_FILE" up $DETACHED

echo "Server starting. Health check available at http://localhost:8080/health"
