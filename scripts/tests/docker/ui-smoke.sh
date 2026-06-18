#!/usr/bin/env bash
#
# scripts/tests/docker/ui-smoke.sh — cross-distro UI-load e2e (feature 0055, Plan A).
#
# Unlike runner.sh (which installs a STUB binary to exercise install.sh
# mechanics offline), this installs a REAL build-release.sh tarball inside a
# <distro> container, starts the install-mode backend (`vulture serve`), and
# asserts the EMBEDDED SPA is actually served — the real app, NOT the
# "Frontend assets not bundled" placeholder — at both `/` and a client-side
# route (`/audit/<id>`, served via the SPA fallback). This is the regression
# guard for the Mode-E embedded-SPA bug: build-release.sh used to run `go build`
# before staging the dist, so every release embedded the placeholder.
#
# Usage: ui-smoke.sh <ubuntu|fedora> <real-tarball.tar.gz>
#   The tarball MUST come from scripts/build-release.sh (embeds the SPA), not
#   build-fixture-tarball.sh (which ships the stub binary).
#
# Exits 0 (PASS) / non-zero (FAIL). Requires Docker + network (installs curl).
set -euo pipefail

DISTRO=${1:?distro (ubuntu|fedora)}
TARBALL=${2:?path to a real build-release.sh tarball (.tar.gz)}
[ -f "$TARBALL" ] || { echo "FAIL [ui/$DISTRO] tarball not found: $TARBALL" >&2; exit 1; }

case "$DISTRO" in
    ubuntu) IMAGE=ubuntu:24.04 ; CURL='apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1' ;;
    fedora) IMAGE=fedora:41    ; CURL='dnf install -y -q curl >/dev/null 2>&1' ;;
    *) echo "FAIL [ui/$DISTRO] unknown distro (want ubuntu|fedora)" >&2; exit 2 ;;
esac

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
FIXDIR=$(cd "$(dirname "$TARBALL")" && pwd)
TARNAME=$(basename "$TARBALL")
# Derive the version install.sh expects from the tarball name:
# vulture-<version>-<os>-<arch>.tar.gz
VER=$(printf '%s' "$TARNAME" | sed -E 's/^vulture-(.*)-(linux|darwin)-(amd64|arm64)\.tar\.gz$/\1/')

echo "==> [ui/$DISTRO] install real tarball ($TARNAME, ver=$VER) + serve + assert SPA"
docker run --rm \
    -v "$FIXDIR":/fix:ro -v "$REPO":/repo:ro \
    -e "TARNAME=$TARNAME" -e "VER=$VER" \
    "$IMAGE" sh -euc '
    '"$CURL"'

    # Writable copy + offline companion fixtures (empty .sig OK with ALLOW_UNSIGNED).
    mkdir -p /work && cp "/fix/$TARNAME" /work/
    ( cd /work && sha256sum "$TARNAME" > SHA256SUMS && : > "${TARNAME%.tar.gz}.sig" )

    export VULTURE_HOME=/root/.vulture
    export VULTURE_OFFLINE_TARBALL="/work/$TARNAME"
    export VULTURE_VERSION="$VER"          # skip the GitHub releases API
    export VULTURE_ALLOW_UNSIGNED=true
    export VULTURE_NO_UPDATE_CHECK=true
    export VULTURE_USE_SYSTEM_PYTHON=0     # CLI-only: the UI does not need agents

    sh /repo/install.sh >/tmp/install.log 2>&1 \
        || { echo "install.sh failed:"; cat /tmp/install.log; exit 1; }

    # Load the generated config (JWT secret, VULTURE_LOCAL_MODE) into the env so
    # the daemon and its serve child start cleanly.
    set -a; . "$VULTURE_HOME/config/.env"; set +a

    # Use the REAL user flow (`vulture start`) — the install-mode launcher runs
    # the binary'\''s `serve` with the correct DataDir/DB-path env. Foreground +
    # background so we can curl then tear down. No agents (CLI-only install) —
    # the launcher serves backend + embedded SPA only.
    "$VULTURE_HOME/bin/vulture" start --foreground >/tmp/serve.log 2>&1 &
    SV=$!

    # Wait for the install-mode backend (127.0.0.1:28080 serves API + embedded SPA).
    up=0
    for _ in $(seq 1 40); do
        if curl -sf -o /dev/null "http://127.0.0.1:28080/"; then up=1; break; fi
        sleep 0.5
    done
    if [ "$up" != 1 ]; then echo "server never came up:"; cat /tmp/serve.log; kill "$SV" 2>/dev/null || true; exit 1; fi

    ROOT=$(curl -s "http://127.0.0.1:28080/")
    ROUTE=$(curl -s "http://127.0.0.1:28080/audit/ui-smoke-test")   # client route -> SPA fallback
    kill "$SV" 2>/dev/null || true

    fail=""
    printf "%s" "$ROOT"  | grep -q  "Frontend assets not bundled"  && fail="$fail placeholder-served-at-root;"
    printf "%s" "$ROOT"  | grep -qE "id=\"root\"|/assets/index-"   || fail="$fail real-SPA-missing-at-root;"
    printf "%s" "$ROUTE" | grep -qE "id=\"root\"|/assets/index-"   || fail="$fail SPA-fallback-broken-for-/audit;"
    if [ -n "$fail" ]; then echo "UI assertions failed:$fail"; exit 1; fi
    echo "UI OK: real embedded SPA served at / and /audit/<id> (no placeholder)"
'
echo "PASS [ui/$DISTRO] embedded SPA loads in $IMAGE"
