#!/usr/bin/env bash
#
# scripts/check-lockfile.sh — feature 0055 B1 freshness gate.
# Re-derives the lockfile and fails if the committed one is stale (a pyproject
# dep changed without a re-lock). Never mutates the working tree. Run by CI and
# by 'vulture.sh release'.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT="agents/requirements-frozen.txt"

if [ ! -f "$OUT" ]; then
    echo "error: $OUT is missing — run 'make freeze-deps' and commit it" >&2
    exit 1
fi

SAVED=$(mktemp)
trap 'cp "$SAVED" "$OUT"; rm -f "$SAVED"' EXIT   # always restore the committed file
cp "$OUT" "$SAVED"

# Capture the generator's output so a generator FAILURE (missing constraint,
# vanished Darwin split, uv mismatch, …) is surfaced with its actionable error
# rather than swallowed into a bare non-zero exit. Distinguish that from an
# actual STALE diff below. The EXIT trap restores the committed file either way.
if ! gen_out=$(scripts/gen-lockfile.sh 2>&1); then
    echo "$gen_out" >&2
    echo "error: lockfile regeneration failed (see above) — not a STALE diff." >&2
    exit 1
fi

if diff -u "$SAVED" "$OUT" >/dev/null 2>&1; then
    echo "lockfile fresh: $OUT"
    exit 0
fi
echo "error: $OUT is STALE — a pyproject dep changed without a re-lock." >&2
echo "       run 'make freeze-deps' and commit the result." >&2
exit 1
