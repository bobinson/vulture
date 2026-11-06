#!/usr/bin/env bash
#
# scripts/gen-lockfile.sh — feature 0055 B1.
# Generate the hashed agent-dependency lockfile (agents/requirements-frozen.txt)
# from the agents' pyproject.toml ranges. Third-party deps only: the first-party
# vulture-* packages load via PYTHONPATH and are never pip-installed, so they are
# stripped from the resolver input.
#
# Three more lockfiles come from the same run, under the same cooldown, for the
# test and tool environments (scripts/locked-venv.sh builds every environment from
# a lockfile):
#   agents/requirements-dev-frozen.txt     every pin above, held, plus the agents'
#                                          `dev` extras (the test tools)
#   mcp/requirements-dev-frozen.txt        mcp/pyproject.toml's deps and `dev` extra
#   scripts/requirements-tools-frozen.txt  scripts/requirements-tools.in (ruff,
#                                          pip-audit), every dev pin held
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
DEV_OUT="agents/requirements-dev-frozen.txt"
MCP_OUT="mcp/requirements-dev-frozen.txt"
TOOLS_OUT="scripts/requirements-tools-frozen.txt"

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

# 1. The constraint file (LLD 0055 B1a) holds what the pyproject ranges cannot:
#    security floors on transitive dependencies, and a per-platform pin should a
#    release target ever lack a wheel for a package's latest version. With the
#    tool list (scripts/requirements-tools.in) it is the only hand-maintained
#    lockfile input, and check-lockfile.sh inherits both by calling this script.
CONSTRAINTS="agents/lockfile-constraints.txt"
# REQUIRE the constraint (feature 0056 M1): without it, `--universal` resolves
# fine but to the WRONG answer — below the floors, onto versions the pip-audit
# gate flags. A missing constraint is a hard error, not a silent fallback.
[ -f "$CONSTRAINTS" ] || {
    echo "error: required constraint file $CONSTRAINTS is missing." >&2
    echo "       it holds the security floors; without it the lockfile can" >&2
    echo "       resolve versions with known advisories." >&2
    exit 1
}

# Stable input paths (NOT mktemp): uv records the input path in '# via -r <path>'
# provenance comments, so a random temp name makes the lockfile non-deterministic
# and breaks check-lockfile.sh. A fixed relative path keeps those comments stable.
mkdir -p build
IN="build/agent-deps.in"
DEV_IN="build/agent-dev-deps.in"
MCP_IN="build/mcp-dev-deps.in"
TOOLS_IN="scripts/requirements-tools.in"
PINS="build/agent-runtime-pins.txt"
DEV_PINS="build/agent-dev-pins.txt"
TMP=$(mktemp)
DEV_TMP=$(mktemp)
MCP_TMP=$(mktemp)
TOOLS_TMP=$(mktemp)
trap 'rm -f "$TMP" "$DEV_TMP" "$MCP_TMP" "$TOOLS_TMP"' EXIT

# 2. third_party_deps <extra> <pyproject>... — every third-party requirement of
#    the pyprojects, plus their <extra> optional dependencies ("" for none),
#    dropping first-party 'vulture-*' deps (PYTHONPATH-loaded, never installed).
third_party_deps() {
    python3 - "$@" <<'PY'
import sys, tomllib
extra, files = sys.argv[1], sorted(sys.argv[2:])
specs = {}
for f in files:
    project = tomllib.load(open(f, "rb")).get("project", {})
    deps = project.get("dependencies", []) + project.get("optional-dependencies", {}).get(extra, [])
    for dep in deps:
        name = dep.replace("[", " ").split()[0]
        for sep in (">", "<", "=", "~", "!", ";", " "):
            name = name.split(sep)[0]
        if not name.strip().lower().startswith("vulture-"):
            specs[dep] = None      # de-dup, preserve the spec
for s in specs:
    print(s)
PY
}
third_party_deps "" agents/*/pyproject.toml > "$IN"
third_party_deps dev agents/*/pyproject.toml > "$DEV_IN"
third_party_deps dev mcp/pyproject.toml > "$MCP_IN"

# 3. Resolve to hash-pinned lockfiles targeting the 3.12 floor. Always universal
#    lockfiles — a universal→host fallback is fatal (M1/M6, below), since a
#    host-only lockfile drops the per-platform marker splits.
#
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

UV_ARGS=(--generate-hashes --no-header --quiet --python-version 3.12)
UV_ARGS+=(--constraint "$CONSTRAINTS")
UV_ARGS+=(--exclude-newer "$LOCK_DATE")
# Per-package snapshot exceptions (comments and blank lines ignored): a new
# dependency newer than LOCK_DATE is admitted without moving any existing pin.
LOCK_DATE_PACKAGES="scripts/lock-date-packages.txt"
if [ -f "$LOCK_DATE_PACKAGES" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"; line="${line//[[:space:]]/}"
        [ -n "$line" ] && UV_ARGS+=(--exclude-newer-package "$line")
    done < "$LOCK_DATE_PACKAGES"
fi
case "${1:-}" in
    --upgrade)     UV_ARGS+=(--upgrade) ;;
    --upgrade-pkg) UV_ARGS+=(--upgrade-package "${2:?--upgrade-pkg needs a name}") ;;
esac

# compile <in> <out> [uv args...] — resolve <in> universally into <out>.
# Fail CLOSED on a universal→host fallback (feature 0056 M1/M6). A host-only
# lockfile silently omits the pins the other release platforms need (and any
# per-platform marker split), so their builds fail with "no usable wheels".
# Any universal failure is fatal here — never emit a host-only lockfile.
compile() {
    local in=$1 out=$2
    shift 2
    if ! uv pip compile "$in" "${UV_ARGS[@]}" "$@" --universal -o "$out" 2>/dev/null; then
        echo "error: 'uv pip compile --universal' could not resolve $in." >&2
        echo "       refusing to fall back to a host-only lockfile (it would omit" >&2
        echo "       the pins the other release platforms need)." >&2
        exit 1
    fi
}
MODE="universal"

compile "$IN" "$TMP"
# The dev lockfile holds every runtime pin: the fresh runtime lockfile is one of
# its constraints, so the tests run against exactly the versions that ship. The
# tools lockfile holds every dev pin the same way, so CI lints with the ruff the
# agents' dev extra names.
cp "$TMP" "$PINS"
compile "$DEV_IN" "$DEV_TMP" --constraint "$PINS"
cp "$DEV_TMP" "$DEV_PINS"
compile "$MCP_IN" "$MCP_TMP"
compile "$TOOLS_IN" "$TOOLS_TMP" --constraint "$DEV_PINS"

# write_lock <tmp> <out> <source of truth>... — the committed file: the header,
# then the resolved pins.
write_lock() {
    local tmp=$1 out=$2
    shift 2
    {
        echo "# GENERATED by scripts/gen-lockfile.sh ($MODE) — DO NOT EDIT BY HAND."
        echo "# Regenerate with 'make freeze-deps' (then commit). Source of truth:"
        printf '# %s\n' "$@"
        cat "$tmp"
    } > "$out"
    echo "wrote $out — $(grep -c -- '--hash=' "$out") hash lines, mode=$MODE"
}

# Only now, after every resolution has succeeded, write the committed files.
write_lock "$TMP" "$OUT" \
    "the agents' pyproject.toml dependency ranges (first-party vulture-*" \
    "packages are excluded; they load via PYTHONPATH)."
write_lock "$DEV_TMP" "$DEV_OUT" \
    "every pin of $OUT, held, plus the agents' \`dev\` extras" \
    "(first-party vulture-* packages are excluded; they load via PYTHONPATH)."
write_lock "$MCP_TMP" "$MCP_OUT" \
    "mcp/pyproject.toml's dependency ranges and its \`dev\` extra (vulture-mcp" \
    "itself loads from the checkout)."
write_lock "$TOOLS_TMP" "$TOOLS_OUT" \
    "$TOOLS_IN, with every pin of $DEV_OUT held."
