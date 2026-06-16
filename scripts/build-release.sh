#!/usr/bin/env bash
#
# scripts/build-release.sh — produces one per-platform tarball for
# the native installer (feature 0044). Runs in CI's release matrix
# and locally for testing.
#
# Usage:
#   scripts/build-release.sh <version> <os> <arch>
#
# Example:
#   scripts/build-release.sh v0.1.0 linux amd64
#
# Output:
#   dist/vulture-<version>-<os>-<arch>.tar.gz
#   dist/SHA256SUMS  (appended)
#
# This script is shellcheck-clean.

set -euo pipefail

VERSION=${1:-}
OS=${2:-$(uname -s | tr '[:upper:]' '[:lower:]')}
ARCH=${3:-$(uname -m)}

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [os] [arch]" >&2
    exit 1
fi
case "$ARCH" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
esac

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$REPO_ROOT/scripts/lib/hash.sh"
DIST=$REPO_ROOT/dist
STAGE=$(mktemp -d)
TARBALL=$DIST/vulture-${VERSION}-${OS}-${ARCH}.tar.gz

mkdir -p "$DIST"

echo "==> Building frontend"
if [ -d "$REPO_ROOT/frontend/dist" ]; then
    echo "    using existing frontend/dist/"
else
    ( cd "$REPO_ROOT/frontend" && npm ci --silent && npm run build --silent )
fi
if [ ! -f "$REPO_ROOT/frontend/dist/index.html" ]; then
    echo "Error: frontend/dist/index.html missing after build" >&2
    exit 1
fi

# Embed the built SPA into the binary. `//go:embed all:frontend` bakes
# backend/internal/assets/frontend/ at COMPILE time; the repo ships only a
# placeholder index.html there, so the real dist must be swapped in BEFORE
# `go build` and the placeholder restored afterward (the dir is git-tracked, so
# restoring keeps local/dev trees clean). The install-mode daemon serves this
# embedded FS via assets.FrontendFS() (server.go registerStaticHandler) — there
# is NO separate runtime/frontend served from disk.
EMBED_DIR="$REPO_ROOT/backend/internal/assets/frontend"
EMBED_BAK=$(mktemp -d)
cp -R "$EMBED_DIR/." "$EMBED_BAK/"
restore_embed() {
    rm -rf "${EMBED_DIR:?}"/*
    cp -R "$EMBED_BAK/." "$EMBED_DIR/"
    rm -rf "$EMBED_BAK"
}
trap restore_embed EXIT INT TERM
rm -rf "${EMBED_DIR:?}"/*
cp -R "$REPO_ROOT/frontend/dist/." "$EMBED_DIR/"

echo "==> Cross-compiling Go binary for ${OS}/${ARCH} (embedding SPA)"
mkdir -p "$STAGE/bin"
( cd "$REPO_ROOT/backend" && \
  GOOS="$OS" GOARCH="$ARCH" CGO_ENABLED=0 \
  go build -tags installmode -trimpath \
    -ldflags "-s -w -buildid= -X main.Version=${VERSION}" \
    -o "$STAGE/bin/vulture" ./cmd/vulture )

# Regression guard: the binary MUST embed the real SPA, not the placeholder.
# (Before this ordering fix, `go build` ran before the dist was staged, so every
# release embedded the placeholder and Mode-E showed "Frontend assets not
# bundled".) Cross-arch safe — we scan the binary's bytes, never run it.
if grep -qa 'Frontend assets not bundled' "$STAGE/bin/vulture"; then
    echo "Error: built binary still embeds the placeholder SPA — frontend not bundled" >&2
    exit 1
fi

echo "==> Copying agents source"
mkdir -p "$STAGE/runtime/agents"
for agent in shared chaos_engineering owasp soc2 cwe xss ssdf asvs do178c discover prove; do
    [ -d "$REPO_ROOT/agents/$agent" ] || continue
    rsync -a --exclude='__pycache__' --exclude='.venv' --exclude='*.egg-info' \
        "$REPO_ROOT/agents/$agent" "$STAGE/runtime/agents/"
done

echo "==> Copying catalogs"
mkdir -p "$STAGE/runtime/catalogs"
if [ -f "$REPO_ROOT/agents/cwe/cwe_agent/data/cwe_catalog.json" ]; then
    cp "$REPO_ROOT/agents/cwe/cwe_agent/data/cwe_catalog.json" "$STAGE/runtime/catalogs/"
fi
if [ -f "$REPO_ROOT/agents/asvs/asvs_agent/data/asvs_catalog.json" ]; then
    cp "$REPO_ROOT/agents/asvs/asvs_agent/data/asvs_catalog.json" "$STAGE/runtime/catalogs/"
fi

echo "==> Staging requirements-frozen.txt (hashed lockfile)"
# Ship the committed, hashed lockfile (scripts/gen-lockfile.sh via
# `make freeze-deps`) so install.sh's VULTURE_USE_SYSTEM_PYTHON path can
# install agent deps with --require-hashes. If it is missing or unhashed,
# ship an empty marker instead: the install stays CLI-only (fail-closed)
# rather than shipping unverified deps. (The previous version globbed
# agents/*/requirements.txt, which never existed — agents use pyproject.toml
# — so it always shipped a 0-byte file.)
_lock="$REPO_ROOT/agents/requirements-frozen.txt"
if grep -q -- '--hash=' "$_lock" 2>/dev/null; then
    cp "$_lock" "$STAGE/runtime/agents/requirements-frozen.txt"
    echo "    shipped hashed lockfile ($(grep -c -- '--hash=' "$_lock") hashes)"
else
    : > "$STAGE/runtime/agents/requirements-frozen.txt"
    echo "    WARNING: no hashed lockfile at agents/requirements-frozen.txt — CLI-only build" >&2
fi

echo "==> python-build-standalone (NOT bundled — Tier B deferred)"
# Tier B (bundling python-build-standalone) is NOT yet wired: neither this
# script nor release.yml fetches PBS — the vendor-pbs-* workflow exists but
# nothing consumes it. See docs/features/0055_native_installer_hardening/
# 0055_implementation_status.md. Until wired, native agent execution requires
# VULTURE_USE_SYSTEM_PYTHON=1 against a host python3.12 (using the hashed
# lockfile staged above); otherwise the install is CLI-only.
PBS_NOTE="$STAGE/runtime/python/PBS_NOT_BUNDLED"
mkdir -p "$STAGE/runtime/python/bin"
cat > "$PBS_NOTE" <<EOF
This tarball does NOT bundle python-build-standalone (Tier B deferred).
Native agent execution requires either a future bundled-runtime release, or
VULTURE_USE_SYSTEM_PYTHON=1 with a host python3.12 (which installs the
hashed requirements-frozen.txt shipped alongside this marker).
EOF

echo "==> Writing VERSION"
echo "$VERSION" > "$STAGE/VERSION"

echo "==> Building reproducible tarball"
# Reproducible: sorted, fixed mtime, no owners, gzip -n strips
# timestamp metadata. --sort/--mtime/--owner require GNU tar; macOS
# runners ship BSD tar, so prefer gtar (Homebrew 'gnu-tar') and fall
# back to a GNU 'tar' if it is the default.
if command -v gtar >/dev/null 2>&1; then
    TAR=gtar
elif tar --version 2>/dev/null | grep -q 'GNU tar'; then
    TAR=tar
else
    echo "Error: GNU tar required for reproducible tarballs" \
         "(install 'gnu-tar', which provides gtar)" >&2
    exit 1
fi
( cd "$STAGE" && \
  "$TAR" --sort=name \
      --mtime='2020-01-01 00:00:00Z' \
      --owner=0 --group=0 --numeric-owner \
      -cf - . | gzip -9n > "$TARBALL" )

SHA=$(sha256_of "$TARBALL")
echo "${SHA}  $(basename "$TARBALL")" >> "$DIST/SHA256SUMS"

rm -rf "$STAGE"

echo ""
echo "==> Built $TARBALL ($(du -h "$TARBALL" | awk '{print $1}'))"
echo "    SHA256: $SHA"
