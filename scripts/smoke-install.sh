#!/usr/bin/env bash
#
# scripts/smoke-install.sh — end-to-end happy-path test for the
# native installer (feature 0044). Used by CI and by developers
# verifying install.sh changes locally.
#
# Usage:
#   scripts/smoke-install.sh <tarball.tar.gz>
#
# What it asserts:
#   - install.sh completes without sudo
#   - vulture binary is reachable from ~/.local/bin
#   - vulture version exits 0
#   - vulture doctor --no-update-check is not FAIL
#   - vulture uninstall --yes leaves no residue
#
# Run from a clean machine (CI runner or a containerized smoke env).

set -euo pipefail

TARBALL=${1:-}
if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "usage: $0 <vulture-*.tar.gz>" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$REPO_ROOT/scripts/lib/hash.sh"
SMOKE_HOME=$(mktemp -d)/vulture-smoke
SMOKE_HOME_REAL=$(readlink -f "$SMOKE_HOME" 2>/dev/null || echo "$SMOKE_HOME")
TARBALL_REAL=$(readlink -f "$TARBALL" 2>/dev/null || echo "$TARBALL")

# Work on an isolated COPY of the tarball: the offline-install path writes
# companion fixtures (SHA256SUMS + an empty .sig) next to it, and we must NOT
# pollute the tarball's source dir — in CI that dir is dist/, which is uploaded
# verbatim as the release assets (an empty .sig there breaks the GH upload).
SMOKE_WORK=$(mktemp -d)
cp "$TARBALL_REAL" "$SMOKE_WORK/"
OFFLINE_TARBALL="$SMOKE_WORK/$(basename "$TARBALL_REAL")"

echo "==> smoke install into $SMOKE_HOME"

# Use the offline-tarball path so we don't need a real GH release.
export VULTURE_HOME="$SMOKE_HOME_REAL"
export VULTURE_OFFLINE_TARBALL="$OFFLINE_TARBALL"
export VULTURE_NO_UPDATE_CHECK=true
export VULTURE_ALLOW_UNSIGNED=true   # local builds aren't cosign-signed
# Force CLI-only so the smoke test stays fast and deterministic: with AUTO
# detect (the default), a runner that happens to have Python 3.12/3.13 would
# pull the entire hash-pinned agent closure (~80 PyPI wheels) on every release
# build × platform, making releases slow and PyPI-flaky. The smoke test verifies
# installer MECHANICS (download/verify/extract/CLI/doctor/uninstall); the
# system-Python agent-install path is covered by the docker e2e matrix
# (scripts/tests/docker) on controlled interpreters.
export VULTURE_USE_SYSTEM_PYTHON=0

# Prepare offline-companion fixtures beside the COPY (never the source dir).
SHASUM_PATH=${OFFLINE_TARBALL%.tar.gz}.SHA256SUMS
TARBALL_NAME=$(basename "$OFFLINE_TARBALL")
SUM=$(sha256_of "$OFFLINE_TARBALL")
printf '%s  %s\n' "$SUM" "$TARBALL_NAME" > "$SHASUM_PATH"
: > "${OFFLINE_TARBALL%.tar.gz}.sig"   # empty sig OK with ALLOW_UNSIGNED

# Run installer. Note: we run a shell-piped invocation rather than
# bash -x so we can see real failure paths.
echo "==> running install.sh"
sh "$REPO_ROOT/install.sh" || { echo "FAIL: install.sh exited non-zero"; exit 1; }

# Assert binary is reachable at the documented path.
BIN="$SMOKE_HOME_REAL/bin/vulture"
if [ ! -x "$BIN" ]; then
    echo "FAIL: $BIN is not executable"; exit 1
fi

# Assert VERSION file exists.
if [ ! -f "$SMOKE_HOME_REAL/VERSION" ]; then
    echo "FAIL: VERSION file missing"; exit 1
fi

# Assert config/.env exists with mode 0600 and a real JWT secret.
ENVFILE="$SMOKE_HOME_REAL/config/.env"
[ -f "$ENVFILE" ] || { echo "FAIL: config/.env missing"; exit 1; }
MODE=$(stat -c '%a' "$ENVFILE" 2>/dev/null || stat -f '%Lp' "$ENVFILE" 2>/dev/null)
if [ "$MODE" != "600" ]; then
    echo "FAIL: config/.env mode = $MODE, want 600"; exit 1
fi
if ! grep -qE '^VULTURE_JWT_SECRET=[a-f0-9]{64}$' "$ENVFILE"; then
    echo "FAIL: VULTURE_JWT_SECRET is not 64 hex chars"; exit 1
fi

# Smoke: vulture version
"$BIN" version | grep -q "vulture" || { echo "FAIL: vulture version output"; exit 1; }

# Doctor (in install mode VULTURE_HOME is set above so DetectMode finds it).
# Local builds may omit python-build-standalone — accept FAIL on the
# python check if PBS_NOT_BUNDLED marker is present.
set +e
"$BIN" doctor --no-update-check
DOCTOR_RC=$?
set -e
PBS_MARKER="$SMOKE_HOME_REAL/runtime/python/PBS_NOT_BUNDLED"
if [ "$DOCTOR_RC" -ne 0 ] && [ "$DOCTOR_RC" -ne 2 ]; then
    if [ -f "$PBS_MARKER" ]; then
        echo "    (local build without PBS — doctor FAIL on python is expected)"
    else
        echo "FAIL: doctor exit = $DOCTOR_RC (want 0 or 2/WARN)"; exit 1
    fi
fi

# Uninstall cleanly.
echo "==> running vulture uninstall --yes"
"$BIN" uninstall --yes || { echo "FAIL: uninstall non-zero"; exit 1; }
if [ -d "$SMOKE_HOME_REAL" ]; then
    echo "FAIL: $SMOKE_HOME_REAL still present after uninstall"; exit 1
fi

echo ""
echo "==> smoke install: PASS"
