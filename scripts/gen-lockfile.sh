#!/usr/bin/env bash
#
# scripts/gen-lockfile.sh — feature 0055 B1.
# Generate the hashed agent-dependency lockfile (agents/requirements-frozen.txt)
# from the agents' pyproject.toml ranges. Third-party deps only: the first-party
# vulture-* packages load via PYTHONPATH and are never pip-installed, so they are
# stripped from the resolver input.
#
# Usage:
#   scripts/gen-lockfile.sh                 # lock to current in-range versions
#   scripts/gen-lockfile.sh --upgrade       # refresh all to latest in-range
#   scripts/gen-lockfile.sh --upgrade-pkg <name>
#
# Output is committed and reviewed; never hand-edit it. CI's check-lockfile.sh
# fails if the committed file is stale.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT="agents/requirements-frozen.txt"

# Pin uv for reproducible lockfiles: a different uv can resolve different versions
# or order hashes differently, which would make check-lockfile.sh's
# re-derive-and-diff flap. Use exactly this uv; set VULTURE_ALLOW_UV_MISMATCH=true
# to override (expect a lockfile diff if you do). The pin's single source of
# truth is scripts/uv-version.sh (feature 0056 M8) — sourced here, also read by
# the setup-pinned-uv CI action; bump uv by editing that one line.
# shellcheck source=scripts/uv-version.sh disable=SC1091
. "$ROOT/scripts/uv-version.sh"
_uv_have=$(uv --version 2>/dev/null | awk '{print $2}') || true
if [ "$_uv_have" != "$UV_VERSION" ] && [ "${VULTURE_ALLOW_UV_MISMATCH:-}" != "true" ]; then
    echo "error: gen-lockfile.sh needs uv $UV_VERSION for reproducible output (found '${_uv_have:-none}')." >&2
    echo "       install it (e.g. 'pipx install uv==$UV_VERSION'), or set" >&2
    echo "       VULTURE_ALLOW_UV_MISMATCH=true to bypass (the lockfile may then differ)." >&2
    exit 1
fi

# Stable input path (NOT mktemp): uv records the input path in '# via -r <path>'
# provenance comments, so a random temp name makes the lockfile non-deterministic
# and breaks check-lockfile.sh. A fixed relative path keeps those comments stable.
mkdir -p build
IN="build/agent-deps.in"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# 1. Aggregate every third-party requirement across all agent pyprojects,
#    dropping first-party 'vulture-*' deps (PYTHONPATH-loaded, never installed).
python3 - <<'PY' > "$IN"
import glob, tomllib
specs = {}
for f in sorted(glob.glob("agents/*/pyproject.toml")):
    data = tomllib.load(open(f, "rb"))
    for dep in data.get("project", {}).get("dependencies", []):
        name = dep.replace("[", " ").split()[0]
        for sep in (">", "<", "=", "~", "!", ";", " "):
            name = name.split(sep)[0]
        if not name.strip().lower().startswith("vulture-"):
            specs[dep] = None      # de-dup, preserve the spec
for s in specs:
    print(s)
PY

# 2. Resolve to a hash-pinned lockfile targeting the 3.12 floor. Always a single
#    universal lockfile — a universal→host fallback is fatal (M1/M6, below), since
#    a host-only lockfile drops the per-platform marker splits.
#    The constraint file (LLD 0055 B1a) marker-splits the few packages whose latest
#    version lacks a wheel on some target — currently cryptography on Intel macOS;
#    uv forks those into per-platform pins. It is the only hand-maintained lockfile
#    input, and check-lockfile.sh inherits it by calling this script.
CONSTRAINTS="agents/lockfile-constraints.txt"
# REQUIRE the constraint (feature 0056 M1): without it, `--universal` resolves
# fine but to the WRONG answer — it drops the Darwin cryptography split and
# re-breaks the darwin/amd64 leg ("no usable wheels"). A missing constraint is a
# hard error, not a silent host-platform fallback.
[ -f "$CONSTRAINTS" ] || {
    echo "error: required constraint file $CONSTRAINTS is missing." >&2
    echo "       it marker-splits the Darwin cryptography pin; without it the" >&2
    echo "       lockfile drops the split and the darwin/amd64 build breaks." >&2
    exit 1
}

# Deterministic re-resolution (feature 0056 M5): resolve against a frozen index
# snapshot date committed in scripts/lock-date.txt so check-lockfile.sh diffs
# repo-to-repo, not repo-to-live-PyPI — an unrelated in-range patch release no
# longer reds an innocent PR. Bump the date only on an intentional relock.
LOCK_DATE_FILE="scripts/lock-date.txt"
[ -f "$LOCK_DATE_FILE" ] || {
    echo "error: required $LOCK_DATE_FILE is missing (the --exclude-newer date)." >&2
    exit 1
}
LOCK_DATE=$(cat "$LOCK_DATE_FILE")

UV_ARGS=(pip compile "$IN" --generate-hashes --no-header --quiet --python-version 3.12)
UV_ARGS+=(--constraint "$CONSTRAINTS")
UV_ARGS+=(--exclude-newer "$LOCK_DATE")
case "${1:-}" in
    --upgrade)     UV_ARGS+=(--upgrade) ;;
    --upgrade-pkg) UV_ARGS+=(--upgrade-package "${2:?--upgrade-pkg needs a name}") ;;
esac

# Fail CLOSED on a universal→host fallback (feature 0056 M1/M6). A host-only
# lockfile silently omits the per-platform marker splits (e.g. the Darwin
# cryptography cap), re-introducing the darwin/amd64 "no usable wheels" failure.
# `--universal` resolving to the wrong answer is the real hole, so any universal
# failure is fatal here — never emit a host-only lockfile.
if ! uv "${UV_ARGS[@]}" --universal -o "$TMP" 2>/dev/null; then
    echo "error: 'uv pip compile --universal' could not resolve." >&2
    echo "       refusing to fall back to a host-only lockfile (it would drop the" >&2
    echo "       per-platform marker splits and break the darwin/amd64 build)." >&2
    exit 1
fi
MODE="universal"

# Assert the Darwin split survived (feature 0056 M1/M6) BEFORE touching $OUT.
# uv emits the marker in SINGLE-quote form (the constraint file uses double
# quotes); match uv's output shape. If it's absent the universal resolve produced
# a no-split lockfile and the darwin/amd64 leg would fail — fail closed WITHOUT
# overwriting the committed file, so a failed assert can never leave a corrupt,
# split-less lockfile on disk (the M1 fail-dirty trap). $TMP is cleaned by the
# EXIT trap.
if ! grep -Eq "^cryptography==[0-9][0-9.]* ; sys_platform == 'darwin'" "$TMP"; then
    echo "error: generated lockfile is missing the Darwin cryptography split" >&2
    echo "       (cryptography==… ; sys_platform == 'darwin'). The marker split" >&2
    echo "       did not survive resolution — the darwin/amd64 build would break." >&2
    echo "       refusing to overwrite $OUT with a split-less lockfile." >&2
    exit 1
fi

# Only now, after every fail-closed check has passed, write the committed file.
{
    echo "# GENERATED by scripts/gen-lockfile.sh ($MODE) — DO NOT EDIT BY HAND."
    echo "# Regenerate with 'make freeze-deps' (then commit). Source of truth:"
    echo "# the agents' pyproject.toml dependency ranges (first-party vulture-*"
    echo "# packages are excluded; they load via PYTHONPATH)."
    cat "$TMP"
} > "$OUT"

echo "wrote $OUT — $(grep -c -- '--hash=' "$OUT") hash lines, mode=$MODE"
