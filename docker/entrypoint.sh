#!/bin/sh
# Container entrypoint.
#
# The core already knows how to write a starter configuration, but the one it
# writes binds the control API to loopback, which is unreachable from outside a
# container. Writing the container's own starter config first means a bare
# `docker compose up -d` produces something usable, while an existing
# /data/config.yaml is never touched.
set -eu

home="${CLASH_HOME:-/data}"
mkdir -p "$home"

if [ ! -f "$home/config.yaml" ]; then
    cp /opt/clash/config.yaml "$home/config.yaml"
    echo "clash: wrote a starter configuration to $home/config.yaml"
    echo "clash: edit it (or import a subscription from the dashboard) to add nodes"
fi

# Anything the user passes is forwarded, so `docker run ... --help` works.
exec /app/Clash.Server --home "$home" "$@"
