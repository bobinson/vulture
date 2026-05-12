#!/usr/bin/env bash
#
# scripts/check-fallback-tag.sh — CI lint that enforces plan H2:
# the FALLBACK_TAG baked into install.sh must be `latest - 1` or
# newer. When a critical CVE forces a release yank, the next
# release MUST bump the fallback past the yanked tag (rollback
# plan SI-3).
#
# Usage: scripts/check-fallback-tag.sh [<current-release-tag>]
#
# Exit non-zero if FALLBACK_TAG is more than one minor version
# behind <current-release-tag>.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
INSTALL_SH="$REPO_ROOT/install.sh"

if [ ! -f "$INSTALL_SH" ]; then
    echo "error: $INSTALL_SH not found" >&2
    exit 2
fi

FALLBACK=$(grep -E '^FALLBACK_TAG=' "$INSTALL_SH" | head -1 | cut -d= -f2 | tr -d '"')
if [ -z "$FALLBACK" ]; then
    echo "error: FALLBACK_TAG not found in $INSTALL_SH" >&2
    exit 1
fi

CURRENT=${1:-}
if [ -z "$CURRENT" ]; then
    # No current tag specified; just print the fallback and exit OK.
    echo "FALLBACK_TAG=$FALLBACK (no current tag supplied; OK)"
    exit 0
fi

# Compare via sort -V — newest is last.
ORDERED=$(printf '%s\n%s\n' "$FALLBACK" "$CURRENT" | sort -V)
NEWEST=$(printf '%s\n' "$ORDERED" | tail -1)
if [ "$NEWEST" = "$FALLBACK" ] && [ "$FALLBACK" != "$CURRENT" ]; then
    echo "error: FALLBACK_TAG ($FALLBACK) is newer than current ($CURRENT)" >&2
    exit 1
fi
if [ "$FALLBACK" = "$CURRENT" ]; then
    echo "warning: FALLBACK_TAG equals current; bump for next release" >&2
fi

echo "FALLBACK_TAG=$FALLBACK, current=$CURRENT: OK"
