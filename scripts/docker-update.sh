#!/bin/sh
# One-click upgrade of the container deployment, for Linux hosts.
#
#   ./scripts/docker-update.sh              # pull the published image
#   ./scripts/docker-update.sh --build      # rebuild from this checkout
#   ./scripts/docker-update.sh --keep-old   # do not prune the replaced image
#
# The data volume is never touched: profiles, the configuration and the fake-IP
# store all survive the upgrade.
set -eu

build=0
keep_old=0
compose_file="$(cd "$(dirname "$0")/.." && pwd)/docker-compose.yml"

for arg in "$@"; do
    case "$arg" in
        --build) build=1 ;;
        --keep-old) keep_old=1 ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo 'docker was not found on PATH. Install the Docker engine first.' >&2
    exit 1
fi

if [ ! -f "$compose_file" ]; then
    echo "no compose file at $compose_file" >&2
    exit 1
fi

# Compose v2 ships as a docker subcommand; v1 is a separate binary.
if docker compose version >/dev/null 2>&1; then
    compose() { docker compose -f "$compose_file" "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
    echo 'docker compose v2 not available; falling back to docker-compose' >&2
    compose() { docker-compose -f "$compose_file" "$@"; }
else
    echo 'neither "docker compose" nor "docker-compose" is available' >&2
    exit 1
fi

echo '==> current state'
compose ps

if [ "$build" -eq 1 ]; then
    echo '==> building the image from this checkout'
    compose build --pull
else
    echo '==> pulling the published image'
    compose pull
fi

echo '==> recreating the container'
# `up -d` only recreates what changed, and leaves the volume alone.
compose up -d --remove-orphans

if [ "$keep_old" -eq 0 ]; then
    echo '==> removing the image that is no longer referenced'
    # Dangling images only: a running or tagged image is never touched.
    docker image prune --force --filter dangling=true >/dev/null
fi

echo '==> waiting for the core to answer'
port=9090
deadline=$(( $(date +%s) + 60 ))
version=''
while [ "$(date +%s)" -lt "$deadline" ]; do
    if command -v curl >/dev/null 2>&1; then
        version="$(curl -fsS "http://127.0.0.1:$port/version" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        version="$(wget -qO- "http://127.0.0.1:$port/version" 2>/dev/null || true)"
    else
        echo 'neither curl nor wget is available; skipping the version check' >&2
        exit 0
    fi
    [ -n "$version" ] && break
    sleep 1
done

if [ -n "$version" ]; then
    echo
    echo "upgraded: $version"
    echo "dashboard: http://127.0.0.1:$port/ui"
else
    echo
    echo 'the container started but the core is not answering yet.' >&2
    echo "check the logs: compose -f $compose_file logs --tail 50" >&2
    exit 1
fi
