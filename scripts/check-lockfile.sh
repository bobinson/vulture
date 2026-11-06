#!/usr/bin/env bash
#
# scripts/check-lockfile.sh — feature 0055 B1 freshness gate.
# Re-derives the lockfiles and fails if a committed one is stale (a pyproject
# dep changed without a re-lock). Never mutates the working tree. Run by CI and
# by 'vulture.sh release'.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
# Every lockfile gen-lockfile.sh writes.
LOCKS=(agents/requirements-frozen.txt agents/requirements-dev-frozen.txt mcp/requirements-dev-frozen.txt)

for f in "${LOCKS[@]}"; do
    if [ ! -f "$f" ]; then
        echo "error: $f is missing — run 'make freeze-deps' and commit it" >&2
        exit 1
    fi
done

SAVED=$(mktemp -d)
# shellcheck disable=SC2317  # invoked by the EXIT trap
restore() {   # always restore the committed files
    local f
    for f in "${LOCKS[@]}"; do cp "$SAVED/$f" "$f"; done
    rm -rf "$SAVED"
}
for f in "${LOCKS[@]}"; do
    mkdir -p "$SAVED/$(dirname "$f")"
    cp "$f" "$SAVED/$f"
done
trap restore EXIT

# Capture the generator's output so a generator FAILURE (missing constraint,
# vanished Darwin split, uv mismatch, …) is surfaced with its actionable error
# rather than swallowed into a bare non-zero exit. Distinguish that from an
# actual STALE diff below. The EXIT trap restores the committed files either way.
if ! gen_out=$(scripts/gen-lockfile.sh 2>&1); then
    echo "$gen_out" >&2
    echo "error: lockfile regeneration failed (see above) — not a STALE diff." >&2
    exit 1
fi

stale=()
for f in "${LOCKS[@]}"; do
    diff -u "$SAVED/$f" "$f" >/dev/null 2>&1 || stale+=("$f")
done
if [ ${#stale[@]} -eq 0 ]; then
    echo "lockfiles fresh: ${LOCKS[*]}"
    exit 0
fi
echo "error: STALE: ${stale[*]} — a pyproject dep changed without a re-lock." >&2
echo "       run 'make freeze-deps' and commit the result." >&2
exit 1
