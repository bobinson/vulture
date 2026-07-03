#!/usr/bin/env bash
# Build a REAL release tarball (scripts/build-release.sh — embeds the SPA) and
# run the cross-distro UI-load e2e (ui-smoke.sh) on it: assert the install-mode
# backend serves the real embedded SPA, not the "Frontend assets not bundled"
# placeholder, in each supported distro.
#
# This complements run-matrix.sh: that one tests install.sh MECHANICS with a
# stub binary; this one runs the REAL binary and proves the UI actually loads
# (regression guard for the 0055 Plan-A embedded-SPA bug).
#
# Usage: run-ui-matrix.sh [version] [arch]   (defaults: v0.0.4, amd64)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
VERSION=${1:-v9.9.9}        # must be >= install.sh's FALLBACK_TAG (anti-downgrade guard); v0.0.4 went stale once FALLBACK_TAG advanced to v0.0.6
ARCH=${2:-amd64}
TARBALL="$REPO/dist/vulture-${VERSION}-linux-${ARCH}.tar.gz"

if [ ! -f "$TARBALL" ]; then
    echo "==> building real tarball ($VERSION linux/$ARCH)"
    "$REPO/scripts/build-release.sh" "$VERSION" linux "$ARCH"
fi

pass=0; fail=0; failed=""
for d in ubuntu fedora; do
    echo "================================================================"
    if "$HERE/ui-smoke.sh" "$d" "$TARBALL"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1)); failed="$failed $d"
    fi
done

echo "================================================================"
echo "ui-matrix: $pass passed, $fail failed"
if [ "$fail" -ne 0 ]; then echo "FAILED:$failed"; exit 1; fi
