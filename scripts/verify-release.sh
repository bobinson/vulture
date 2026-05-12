#!/usr/bin/env bash
#
# scripts/verify-release.sh — user-runnable reproducible-build
# verification (plan L3). Rebuilds the release tarball from the
# tagged source and compares its SHA against the published
# SHA256SUMS.
#
# Usage:
#   scripts/verify-release.sh <version>
#
# Example:
#   scripts/verify-release.sh v0.1.0
#
# Toolchain mismatches produce a WARN (not a hard fail) since
# reproducibility requires identical Go / Node / PBS versions.

set -euo pipefail

VERSION=${1:-}
if [ -z "$VERSION" ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
case "$PLATFORM" in
    *x86_64) PLATFORM="${PLATFORM%x86_64}amd64" ;;
    *aarch64) PLATFORM="${PLATFORM%aarch64}arm64" ;;
esac

echo "==> verify-release for $VERSION ($PLATFORM)"

# 1. Check toolchain.
WARN=0
GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' || echo none)
case "$GO_VERSION" in
    go1.24*) ;;
    *) echo "warn: Go version $GO_VERSION is not the canonical go1.24 (reproducibility WARN)"; WARN=1 ;;
esac
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node -v)
    case "$NODE_VERSION" in
        v20.*) ;;
        *) echo "warn: Node version $NODE_VERSION is not the canonical v20.x"; WARN=1 ;;
    esac
fi

# 2. Local rebuild.
DIST=$REPO_ROOT/dist-verify
rm -rf "$DIST"
mkdir -p "$DIST"
( cd "$REPO_ROOT" && DIST_DIR_OVERRIDE="$DIST" scripts/build-release.sh "$VERSION" )

LOCAL_TARBALL=$(ls "$REPO_ROOT/dist/vulture-${VERSION}-${PLATFORM}.tar.gz" 2>/dev/null \
    || ls "$DIST/vulture-${VERSION}-${PLATFORM}.tar.gz" 2>/dev/null || true)
[ -n "$LOCAL_TARBALL" ] || { echo "error: local rebuild produced no tarball" >&2; exit 1; }
LOCAL_SHA=$(sha256sum "$LOCAL_TARBALL" | awk '{print $1}')
echo "  local SHA: $LOCAL_SHA"

# 3. Fetch published SHA256SUMS.
URL_BASE="https://github.com/bobinson/vulture/releases/download/${VERSION}"
PUB=$(mktemp)
curl -fsSL -o "$PUB" "${URL_BASE}/SHA256SUMS" || { echo "error: fetch SHA256SUMS"; exit 1; }
PUB_SHA=$(grep " vulture-${VERSION}-${PLATFORM}.tar.gz$" "$PUB" | awk '{print $1}' || true)
echo "  published SHA: $PUB_SHA"

# 4. Compare.
if [ -z "$PUB_SHA" ]; then
    echo "error: published SHA256SUMS has no entry for this platform" >&2
    exit 1
fi
if [ "$LOCAL_SHA" != "$PUB_SHA" ]; then
    echo "MISMATCH: local rebuild does not match published tarball"
    [ "$WARN" -eq 1 ] && echo "  toolchain WARN above may explain the difference"
    exit 1
fi
echo "==> verify-release: OK (reproducible)"
