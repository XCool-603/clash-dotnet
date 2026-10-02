# syntax=docker/dockerfile:1

# Clash for .NET, headless (core + dashboard).
#
# Only Clash.Server is published: the tray shell targets net10.0-windows and
# cannot build on Linux. TUN mode is therefore not part of this image — it needs
# a Windows driver, and the API that drives it lives in the desktop build.

# ── Dashboard ────────────────────────────────────────────────────────────────
FROM node:22-alpine AS web

WORKDIR /src/web

# Dependencies first, so a source change does not re-download them.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./

# vite writes to ../src/Clash.Server/wwwroot, so the repository layout is
# preserved here rather than flattened.
RUN npm run build

# ── Core ─────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

# Restore against the project files alone; the sources come later.
COPY Directory.Build.props Clash.slnx ./
COPY src/Clash.Core/Clash.Core.csproj src/Clash.Core/
COPY src/Clash.Server/Clash.Server.csproj src/Clash.Server/
RUN dotnet restore src/Clash.Server/Clash.Server.csproj

COPY src/ src/
COPY --from=web /src/src/Clash.Server/wwwroot src/Clash.Server/wwwroot

RUN dotnet publish src/Clash.Server/Clash.Server.csproj \
        -c Release \
        -o /app \
        --no-restore

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

# wintun.dll is deliberately absent: this image has no Windows TUN support.
WORKDIR /app
COPY --from=build /app ./

COPY docker/config.yaml /opt/clash/config.yaml

# --chmod rather than `RUN chmod +x`: a Windows checkout can lose the executable
# bit, and fixing it at COPY time cannot be undone by a later layer.
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/clash-entrypoint

# The data directory is created here so that a *named* volume mounted at /data
# inherits this path's ownership on first use. A bind mount overrides it with the
# host directory's owner, which is why the process runs as root (below).
RUN mkdir -p /data

# The configuration and the profile cache live here, so the container is
# stateless and an upgrade is a pull.
VOLUME ["/data"]

# 7890 is the mixed HTTP/SOCKS proxy, 9090 the control API and dashboard,
# 1053 the DNS listener. Both proxy and DNS carry datagrams, hence udp.
EXPOSE 7890/tcp 7890/udp 9090/tcp 1053/tcp 1053/udp

# Runs as root, deliberately, and this is the one thing to revisit if you harden
# the deployment.
#
# The documented deployment bind-mounts a host directory over /data so the
# configuration can be edited from the host. A bind mount replaces the
# directory's ownership with the host's, so a non-root process cannot write
# config.yaml there — the failure would be an EACCES on the first run, which is
# the worst possible place for it. Root avoids that without asking the user to
# chown anything.
#
# To run unprivileged instead, use a named volume (which inherits /data's
# ownership from this image) and drop the bind mount, then set `user: "10001:10001"`
# on the service. Ports 7890/9090/1053 are all above 1024, so no capability is
# needed.
ENTRYPOINT ["/usr/local/bin/clash-entrypoint"]
