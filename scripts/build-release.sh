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

echo "==> Copying plugin manifests"
# Ship plugin DISCOVERY METADATA only (plugin.toml + CWE rule sidecars), NOT
# container images — those pull at runtime (same deferral posture as PBS). The
# install-mode launcher points VULTURE_BUILTIN_PLUGINS_DIR here so discovery +
# VULTURE_PLUGINS can act on them. Running a container plugin still needs Docker.
if [ -d "$REPO_ROOT/plugins" ]; then
    for d in "$REPO_ROOT"/plugins/*/; do
        [ -f "$d/plugin.toml" ] || continue
        name=$(basename "$d")
        mkdir -p "$STAGE/runtime/plugins/$name"
        cp "$d/plugin.toml" "$STAGE/runtime/plugins/$name/"
        [ -d "$d/rules" ] && cp -R "$d/rules" "$STAGE/runtime/plugins/$name/"
    done
fi

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

# ─── python-build-standalone (Tier B) ──────────────────────────────────────
# OPT-IN at build time: VULTURE_BUNDLE_PBS=1 bundles a CPython 3.12 interpreter
# (python-build-standalone) into runtime/python/ AND pre-installs the hashed
# agent deps into it, so the shipped tarball runs the Python agents OFFLINE with
# NO system Python and NO Docker. When the flag is UNSET the default release
# stays LEAN — we only write the PBS_NOT_BUNDLED marker (today's behaviour).
#
# The fetch+SHA-verify here is the sandbox-runnable equivalent of the
# cosign-signed vendor pipeline (vendor-pbs.yml), which stays CI-only/deferred.
# Linux/amd64 build host only; darwin + the cosign vendor flow are out of scope.
mkdir -p "$STAGE/runtime/python/bin"
if [ "${VULTURE_BUNDLE_PBS:-}" = "1" ] || [ "${VULTURE_BUNDLE_PBS:-}" = "true" ]; then
    echo "==> python-build-standalone (VULTURE_BUNDLE_PBS set — bundling CPython 3.12)"
    if [ "$OS" != linux ] || [ "$ARCH" != amd64 ]; then
        echo "Error: VULTURE_BUNDLE_PBS only supports linux/amd64 build hosts" \
             "(got ${OS}/${ARCH}); darwin is deferred" >&2
        exit 1
    fi

    PBS_REPO=${VULTURE_PBS_REPO:-indygreg/python-build-standalone}
    PBS_TRIPLE=x86_64-unknown-linux-gnu
    # Resolve a real recent PBS tag carrying a CPython 3.12.x install_only build
    # for our triple. Pinned fallback (verified to exist) keeps the build
    # deterministic if the releases API is unreachable.
    PBS_TAG=${VULTURE_PBS_TAG:-}
    PBS_PYVER=${VULTURE_PBS_PYVER:-}
    if [ -z "$PBS_TAG" ] || [ -z "$PBS_PYVER" ]; then
        echo "    resolving latest PBS 3.12.x ${PBS_TRIPLE} tag via releases API"
        _api="https://api.github.com/repos/${PBS_REPO}/releases?per_page=20"
        _asset=$(curl -fsSL "$_api" 2>/dev/null \
            | grep -oE "cpython-3\.12\.[0-9]+\+[0-9]+-${PBS_TRIPLE}-install_only\.tar\.gz" \
            | head -n1 || true)
        if [ -n "$_asset" ]; then
            # cpython-<pyver>+<tag>-<triple>-install_only.tar.gz
            PBS_PYVER=$(printf '%s' "$_asset" | sed -E 's/^cpython-([0-9.]+)\+.*/\1/')
            PBS_TAG=$(printf '%s' "$_asset" | sed -E 's/^cpython-[0-9.]+\+([0-9]+)-.*/\1/')
            echo "    resolved PBS tag=$PBS_TAG python=$PBS_PYVER"
        else
            PBS_TAG=20260610
            PBS_PYVER=3.12.13
            echo "    releases API unavailable — using pinned PBS tag=$PBS_TAG python=$PBS_PYVER" >&2
        fi
    fi

    PBS_ASSET="cpython-${PBS_PYVER}+${PBS_TAG}-${PBS_TRIPLE}-install_only.tar.gz"
    PBS_BASE="https://github.com/${PBS_REPO}/releases/download/${PBS_TAG}"
    PBS_DL=$(mktemp -d)
    echo "    downloading $PBS_ASSET"
    curl -fsSL -o "$PBS_DL/$PBS_ASSET" "$PBS_BASE/$PBS_ASSET" \
        || { echo "Error: failed to download PBS asset $PBS_ASSET" >&2; exit 1; }
    echo "    downloading published SHA256SUMS"
    curl -fsSL -o "$PBS_DL/SHA256SUMS" "$PBS_BASE/SHA256SUMS" \
        || { echo "Error: failed to download PBS SHA256SUMS" >&2; exit 1; }

    # Fail-closed SHA-256 verification against the release's published sums.
    PBS_EXPECTED=$(awk -v f="$PBS_ASSET" '$2==f {print $1}' "$PBS_DL/SHA256SUMS")
    if [ -z "$PBS_EXPECTED" ]; then
        echo "Error: no SHA256 for $PBS_ASSET in published SHA256SUMS (fail-closed)" >&2
        exit 1
    fi
    PBS_ACTUAL=$(sha256_of "$PBS_DL/$PBS_ASSET")
    if [ "$PBS_EXPECTED" != "$PBS_ACTUAL" ]; then
        echo "Error: PBS SHA256 mismatch (fail-closed): got $PBS_ACTUAL want $PBS_EXPECTED" >&2
        exit 1
    fi
    echo "    SHA256 verified: $PBS_ACTUAL"

    # Extract + flatten: the PBS tarball lays everything under a top-level
    # 'python/' dir, so extracting into runtime/ lands bin/ directly under
    # runtime/python/.
    echo "    extracting + flattening into runtime/python/"
    PBS_EXTRACT=$(mktemp -d)
    tar -xzf "$PBS_DL/$PBS_ASSET" -C "$PBS_EXTRACT"
    rm -rf "${STAGE:?}/runtime/python"
    mv "$PBS_EXTRACT/python" "$STAGE/runtime/python"
    rm -rf "$PBS_EXTRACT" "$PBS_DL"

    # PBS ships bin/python3.12 already, but add the alias if a dist only has
    # bin/python3 — the install-mode launcher + doctor expect python3.12.
    if [ ! -e "$STAGE/runtime/python/bin/python3.12" ]; then
        if [ -e "$STAGE/runtime/python/bin/python3" ]; then
            ln -s python3 "$STAGE/runtime/python/bin/python3.12"
        else
            echo "Error: PBS dist has no bin/python3 to alias as python3.12" >&2
            exit 1
        fi
    fi

    # Pre-install the hashed agent deps into the bundled interpreter so the
    # shipped tarball installs OFFLINE (install.sh skips pip when uvicorn imports).
    # 3.12 is REQUIRED (litellm pins <3.14; the >=3.12 floor + <3.14 ceiling
    # already exist). --require-hashes + --only-binary keeps it fail-closed.
    _frozen="$STAGE/runtime/agents/requirements-frozen.txt"
    if grep -q -- '--hash=' "$_frozen" 2>/dev/null; then
        echo "    pip install --require-hashes agent deps into bundled python3.12"
        # PYTHONNOUSERSITE=1 + empty PYTHONPATH: hermetic build. Otherwise the
        # bundled interpreter sees the BUILD host's ~/.local/lib site-packages,
        # pip treats those as "already satisfied", and omits them from the
        # bundled runtime — shipping an incomplete tarball (e.g. missing
        # annotated_doc → fastapi import fails on the target).
        PYTHONNOUSERSITE=1 PYTHONPATH='' "$STAGE/runtime/python/bin/python3.12" -m pip install \
            --require-hashes --only-binary :all: --no-cache-dir \
            --disable-pip-version-check \
            -r "$_frozen" \
            || { echo "Error: bundled pip install (--require-hashes) failed" >&2; exit 1; }
        echo "    agent deps pre-installed into bundled runtime"
    else
        echo "    WARNING: no hashed lockfile — bundled interpreter ships WITHOUT agent deps" >&2
    fi
    echo "==> bundled python-build-standalone $PBS_PYVER (tag $PBS_TAG) into runtime/python/"
else
    echo "==> python-build-standalone (NOT bundled — set VULTURE_BUNDLE_PBS=1 to bundle)"
    # Lean default (Tier B opt-in unset): no fetch/SHA/interpreter — just the
    # marker. Native agent execution then requires VULTURE_USE_SYSTEM_PYTHON=1
    # against a host python3.12 (using the hashed lockfile staged above); else
    # the install is CLI-only. See docs/features/0055_native_installer_hardening/.
    PBS_NOTE="$STAGE/runtime/python/PBS_NOT_BUNDLED"
    cat > "$PBS_NOTE" <<EOF
This tarball does NOT bundle python-build-standalone (built without
VULTURE_BUNDLE_PBS=1). Native agent execution requires either a
VULTURE_BUNDLE_PBS=1 release, or VULTURE_USE_SYSTEM_PYTHON=1 with a host
python3.12 (which installs the hashed requirements-frozen.txt shipped
alongside this marker).
EOF
fi

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
