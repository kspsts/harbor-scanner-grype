#!/usr/bin/env bash
# Deploys the Harbor Scanner Grype adapter with Docker Compose.
# Settings live in .env, created from .env.example on the first run.
#
# Usage:
#   ./deploy.sh                    # log level from .env
#   ./deploy.sh --log-level=debug  # error | warn | info | debug, overrides .env
#   ./deploy.sh --help
set -euo pipefail
cd "$(dirname "$0")"

NETWORK_NAME="harbor_harbor"
LOG_LEVEL=""

for arg in "$@"; do
    case "$arg" in
        --log-level=*) LOG_LEVEL="${arg#*=}" ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg (see --help)" >&2; exit 1 ;;
    esac
done

if [ -n "$LOG_LEVEL" ]; then
    case "$LOG_LEVEL" in
        error|warn|info|debug) export SCANNER_LOG_LEVEL="$LOG_LEVEL" ;;
        *) echo "Invalid log level: $LOG_LEVEL (error, warn, info, debug)" >&2; exit 1 ;;
    esac
fi

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "Network '$NETWORK_NAME' not found. Start Harbor first." >&2
    exit 1
fi

if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example. Review it (credentials, hosts, thresholds) and run ./deploy.sh again."
    exit 0
fi

# Containers from earlier deployments (plain `docker run`, or the old compose file with a
# second "redis" service on Harbor's network) use the same names and must go first.
for name in grype-adapter grype-redis; do
    service=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$name" 2>/dev/null) || continue
    if [ "$service" != "$name" ]; then
        echo "Removing container '$name' left from an earlier deployment"
        docker rm -f "$name" >/dev/null
    fi
done

# Use the local image (from `docker load` or an earlier build); build it from this checkout
# only when it is missing. Keep in sync with `image:` in docker-compose.yml.
IMAGE="ant1freeze/harbor-scanner-grype:latest"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Image $IMAGE not found locally, building it from source"
    docker compose build grype-adapter
fi

docker compose up -d --remove-orphans --wait

docker compose ps
PORT=$(docker compose port grype-adapter 8090 | sed 's/.*://')
if curl -fsS -o /dev/null "http://localhost:$PORT/api/v1/metadata"; then
    echo "API is responding on http://localhost:$PORT"
else
    echo "API is not responding, see: docker compose logs grype-adapter" >&2
    exit 1
fi
