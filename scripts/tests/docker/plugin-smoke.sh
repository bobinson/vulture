#!/usr/bin/env bash
#
# scripts/tests/docker/plugin-smoke.sh — plugin-activation e2e (feature 0055).
#
# Modeled on ui-smoke.sh. Proves the full external-plugin activation path inside
# a fresh ubuntu:24.04 container: tarball discovery (runtime/plugins/semgrep) ->
# the VULTURE_PLUGINS allow-list -> /api/agents surfacing.
#
# It installs the REAL release tarball offline, starts the install-mode launcher
# (`vulture start --foreground`, which serves API + embedded SPA on :28080), and
# runs two cases against the unauthenticated (local-mode) /api/agents endpoint:
#
#   CASE A (default):   config/.env ships VULTURE_PLUGINS= (empty) -> the semgrep
#                       plugin is discovered but DISABLED -> /api/agents must NOT
#                       contain "semgrep".
#   CASE B (activated): VULTURE_PLUGINS=semgrep -> the plugin is enabled ->
#                       /api/agents MUST contain a semgrep entry.
#
# semgrep is surfaced by PRESENCE in the registry allow-list even though its
# container cannot run (no docker-in-docker) — that graceful state is expected;
# this asserts presence, not health.
#
# Usage: plugin-smoke.sh [real-tarball.tar.gz]
#   Defaults to dist/vulture-v0.0.4-linux-amd64.tar.gz.
#
# Exits 0 (PASS) / non-zero (FAIL). Requires Docker + network (installs curl).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TARBALL=${1:-$REPO/dist/vulture-v0.0.4-linux-amd64.tar.gz}
[ -f "$TARBALL" ] || { echo "FAIL [plugin] tarball not found: $TARBALL" >&2; exit 1; }

IMAGE=ubuntu:24.04
FIXDIR=$(cd "$(dirname "$TARBALL")" && pwd)
TARNAME=$(basename "$TARBALL")
# Derive the version install.sh expects from the tarball name:
# vulture-<version>-<os>-<arch>.tar.gz
VER=$(printf '%s' "$TARNAME" | sed -E 's/^vulture-(.*)-(linux|darwin)-(amd64|arm64)\.tar\.gz$/\1/')

echo "==> [plugin] install real tarball ($TARNAME, ver=$VER) + activation A/B on /api/agents"
docker run --rm \
    -v "$FIXDIR":/fix:ro -v "$REPO":/repo:ro \
    -e "TARNAME=$TARNAME" -e "VER=$VER" \
    "$IMAGE" sh -euc '
    apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1

    # Writable copy + offline companion fixtures (empty .sig OK with ALLOW_UNSIGNED).
    mkdir -p /work && cp "/fix/$TARNAME" /work/
    ( cd /work && sha256sum "$TARNAME" > SHA256SUMS && : > "${TARNAME%.tar.gz}.sig" )

    export VULTURE_HOME=/root/.vulture
    export VULTURE_OFFLINE_TARBALL="/work/$TARNAME"
    export VULTURE_VERSION="$VER"          # skip the GitHub releases API
    export VULTURE_ALLOW_UNSIGNED=true
    export VULTURE_NO_UPDATE_CHECK=true
    export VULTURE_USE_SYSTEM_PYTHON=0     # CLI-only: agents need not run for this probe

    sh /repo/install.sh >/tmp/install.log 2>&1 \
        || { echo "install.sh failed:"; cat /tmp/install.log; exit 1; }

    ENVF="$VULTURE_HOME/config/.env"

    # Helper: start the install-mode launcher, wait for :28080, capture
    # /api/agents, tear down. Echoes the agents JSON on stdout.
    fetch_agents() {
        # Load the generated config (JWT secret, VULTURE_LOCAL_MODE, VULTURE_PLUGINS)
        # so the daemon + its serve child start with the right activation list.
        set -a; . "$ENVF"; set +a

        "$VULTURE_HOME/bin/vulture" start --foreground >/tmp/serve.log 2>&1 &
        SV=$!

        up=0
        for _ in $(seq 1 40); do
            if curl -sf -o /dev/null "http://127.0.0.1:28080/api/agents"; then up=1; break; fi
            sleep 0.5
        done
        if [ "$up" != 1 ]; then
            echo "server never came up:" >&2; cat /tmp/serve.log >&2
            kill "$SV" 2>/dev/null || true
            return 1
        fi

        curl -s "http://127.0.0.1:28080/api/agents"
        kill "$SV" 2>/dev/null || true
        # Wait for the port to free up before the next case rebinds it.
        for _ in $(seq 1 20); do
            curl -sf -o /dev/null "http://127.0.0.1:28080/api/agents" || break
            sleep 0.5
        done
        return 0
    }

    # --- CASE A: default seeded VULTURE_PLUGINS= (empty) -> semgrep absent ---
    grep -q "^VULTURE_PLUGINS=$" "$ENVF" \
        || echo "WARN: seeded VULTURE_PLUGINS is not empty in $ENVF:" >&2
    grep "^VULTURE_PLUGINS=" "$ENVF" >&2 || true

    A=$(fetch_agents) || exit 1
    echo "AGENTS_A_BEGIN"; echo "$A"; echo "AGENTS_A_END"

    # --- CASE B: VULTURE_PLUGINS=semgrep -> semgrep present ---
    # Edit config/.env in place so the change flows through the real start path.
    if grep -q "^VULTURE_PLUGINS=" "$ENVF"; then
        sed -i "s/^VULTURE_PLUGINS=.*/VULTURE_PLUGINS=semgrep/" "$ENVF"
    else
        echo "VULTURE_PLUGINS=semgrep" >> "$ENVF"
    fi

    B=$(fetch_agents) || exit 1
    echo "AGENTS_B_BEGIN"; echo "$B"; echo "AGENTS_B_END"

    fail=""
    printf "%s" "$A" | grep -q "semgrep" && fail="$fail CASE-A-semgrep-present-but-should-be-absent;"
    printf "%s" "$B" | grep -q "semgrep" || fail="$fail CASE-B-semgrep-absent-but-should-be-present;"
    if [ -n "$fail" ]; then echo "PLUGIN assertions failed:$fail"; exit 1; fi
    echo "PLUGIN OK: semgrep absent (A) then present (B) via VULTURE_PLUGINS allow-list"
'
echo "PASS [plugin] activation A/B holds in $IMAGE"
