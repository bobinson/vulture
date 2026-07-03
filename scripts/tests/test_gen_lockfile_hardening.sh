#!/usr/bin/env sh
#
# RED-phase tests for the 0056 gen-lockfile hardening (M1 · M5 · M6 · M8).
# Spec: docs/guides/release_hardening_audit.md (M1/M5/M6/M8) +
#       docs/features/0056_release_hardening/0056_implementation_plan.md §3.1.
#
# These assert the desired END-STATE of scripts/gen-lockfile.sh and its new
# single-source inputs (scripts/uv-version.sh, scripts/lock-date.txt). Against
# the pristine (pre-0056) tree they FAIL (expected RED): the script inlines
# UV_VERSION="0.11.21", fails OPEN on a missing constraint (`[ -f … ] && …`),
# has no --exclude-newer / lock-date wiring, and no post-generation Darwin-split
# assertion. This test only asserts the contract; it does not implement it.
#
# Tests are STATIC (grep the committed sources) EXCEPT the constraint-required
# case, which is BEHAVIORAL: it stages a throwaway copy of the generator's tree
# in a sandbox, hides the constraint file, and asserts gen-lockfile.sh exits
# non-zero — proving it fails CLOSED, not silently skips. The behavioral case is
# self-skipping (still a PASS) when `uv` is unavailable, so the suite stays green
# on machines without the pinned toolchain; the static cases always run.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final tally, exit 1 on any FAIL. No bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
GEN="$REPO_ROOT/scripts/gen-lockfile.sh"
UV_VERSION_SH="$REPO_ROOT/scripts/uv-version.sh"
LOCK_DATE="$REPO_ROOT/scripts/lock-date.txt"
CONSTRAINT="$REPO_ROOT/agents/lockfile-constraints.txt"

require_file_or_bail "gen-lockfile-present" "$GEN"

# ---------------------------------------------------------------------------
# TEST 1 (M8) — scripts/uv-version.sh exists and is a BARE assignment file:
# exactly the single source of the pinned uv version. It must NOT be an
# executable script (no shebang, no command logic) — it is *sourced*, so a
# stray `set -e`/exec or a command line would run inside gen-lockfile.sh.
# Contract: every non-blank, non-comment line is `UV_VERSION=<value>`, and at
# least one such line exists.
# ---------------------------------------------------------------------------
require_file_or_bail "uv-version-sh-present" "$UV_VERSION_SH"

test_uv_version_is_bare_assignment() {
    name="uv-version-sh-is-bare-assignment"
    # No shebang on line 1 (it is sourced, never executed).
    if head -n1 "$UV_VERSION_SH" | grep -q '^#!'; then
        fail "$name" "uv-version.sh starts with a shebang — it must be sourced, not executed"
        return
    fi
    # Every meaningful line must be a UV_VERSION assignment; nothing else.
    _stray=$(grep -vE '^[[:space:]]*(#|$)' "$UV_VERSION_SH" \
        | grep -vE '^[[:space:]]*UV_VERSION=' || true)
    if [ -n "$_stray" ]; then
        fail "$name" "uv-version.sh has non-assignment line(s): $_stray"
        return
    fi
    # And the assignment must actually be present.
    if grep -Eq '^[[:space:]]*UV_VERSION=' "$UV_VERSION_SH"; then
        pass "$name"
    else
        fail "$name" "uv-version.sh contains no UV_VERSION= assignment"
    fi
}
test_uv_version_is_bare_assignment

# ---------------------------------------------------------------------------
# TEST 2 (M8) — gen-lockfile.sh SOURCES scripts/uv-version.sh (rather than
# inlining UV_VERSION="…"). Single source of truth for the pin.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016  # ERE pattern for grep; $ROOT etc. are literal, must not expand
assert_file_matches \
    "gen-lockfile-sources-uv-version" \
    "$GEN" \
    '\.[[:space:]]+"\$(\{)?ROOT\}?/scripts/uv-version\.sh"' \
    "gen-lockfile.sh does not source scripts/uv-version.sh (it must '. \"\$ROOT/scripts/uv-version.sh\"', not inline UV_VERSION=)"

# ---------------------------------------------------------------------------
# TEST 3 (M8) — gen-lockfile.sh no longer carries the inline version LITERAL.
# The pin lives only in uv-version.sh; an inline `UV_VERSION="0.11.21"` (or any
# bare quoted version) in the generator means two sources of truth.
# ---------------------------------------------------------------------------
test_gen_has_no_inline_version_literal() {
    name="gen-lockfile-has-no-inline-version-literal"
    if grep -Eq 'UV_VERSION=["'"'"'][0-9]+\.[0-9]+\.[0-9]+' "$GEN"; then
        fail "$name" "gen-lockfile.sh still inlines a UV_VERSION=\"<x.y.z>\" literal (must source uv-version.sh instead)"
    else
        pass "$name"
    fi
}
test_gen_has_no_inline_version_literal

# ---------------------------------------------------------------------------
# TEST 4 (M5) — scripts/lock-date.txt exists and is a single RFC3339-ish UTC
# date line (the frozen index snapshot for deterministic re-resolution).
# ---------------------------------------------------------------------------
require_file_or_bail "lock-date-present" "$LOCK_DATE"
assert_file_matches \
    "lock-date-is-rfc3339-utc" \
    "$LOCK_DATE" \
    '^[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9]{2}:[0-9]{2}:[0-9]{2}Z?)?$' \
    "lock-date.txt is not a single YYYY-MM-DD[THH:MM:SSZ] UTC date line"

# ---------------------------------------------------------------------------
# TEST 5 (M5) — gen-lockfile.sh PASSES --exclude-newer reading lock-date.txt,
# so it resolves against a frozen index date (repo-to-repo, not repo-to-live).
# ---------------------------------------------------------------------------
assert_file_matches \
    "gen-lockfile-passes-exclude-newer" \
    "$GEN" \
    '\-\-exclude-newer' \
    "gen-lockfile.sh passes no --exclude-newer; re-resolution is non-deterministic against live PyPI"
assert_file_matches \
    "gen-lockfile-reads-lock-date" \
    "$GEN" \
    'lock-date\.txt' \
    "gen-lockfile.sh never reads scripts/lock-date.txt for the --exclude-newer value"

# ---------------------------------------------------------------------------
# TEST 6 (M1/M6) — gen-lockfile.sh ASSERTS the resolved Darwin split line in
# uv's SINGLE-QUOTE output form (cryptography==… ; sys_platform == 'darwin').
# It must reference that single-quoted marker shape in an assertion (grep/case),
# not the constraint file's double-quote form.
# ---------------------------------------------------------------------------
test_gen_asserts_darwin_split() {
    name="gen-lockfile-asserts-darwin-split"
    # Look for the single-quoted darwin marker shape used as an assertion target.
    if grep -Eq "sys_platform == 'darwin'" "$GEN" \
       && grep -Eq "cryptography==.*sys_platform == 'darwin'" "$GEN"; then
        pass "$name"
    else
        fail "$name" "gen-lockfile.sh does not assert the single-quote \"cryptography==… ; sys_platform == 'darwin'\" line after generating (M1/M6)"
    fi
}
test_gen_asserts_darwin_split

# ---------------------------------------------------------------------------
# TEST 7 (M1) STATIC — the fail-OPEN constraint pattern is GONE. The old line
# `[ -f "$CONSTRAINTS" ] && UV_ARGS+=(--constraint …)` silently skipped the
# constraint when absent. The hardened form fails closed, so the `&&`-skip must
# not remain.
# ---------------------------------------------------------------------------
test_gen_no_fail_open_constraint() {
    name="gen-lockfile-no-fail-open-constraint"
    # The fail-open idiom: a `[ -f <constraint> ] &&` test that GATES adding the
    # --constraint arg (i.e. silently skips it when the file is absent).
    # shellcheck disable=SC2016  # ERE pattern for grep; $CONSTRAINTS is literal, must not expand
    if grep -Eq '\[ -f "\$CONSTRAINTS?" \][[:space:]]*&&' "$GEN"; then
        fail "$name" "gen-lockfile.sh still uses the fail-OPEN '[ -f \$CONSTRAINT ] && …' skip (M1: must fail closed)"
    else
        pass "$name"
    fi
}
test_gen_no_fail_open_constraint

# ---------------------------------------------------------------------------
# TEST 8 (M1) BEHAVIORAL — with the constraint file HIDDEN, gen-lockfile.sh
# exits NON-ZERO (fails closed). Staged in a sandbox so the real tree is never
# touched. Self-skips (PASS) when `uv` is unavailable.
#
# The sandbox mirrors only what the generator reads relative to its own dir:
#   scripts/gen-lockfile.sh, scripts/uv-version.sh, scripts/lock-date.txt,
#   agents/*/pyproject.toml, agents/lockfile-constraints.txt.
# gen-lockfile.sh derives ROOT from its own path, so a copied script operates
# entirely inside the sandbox.
# ---------------------------------------------------------------------------
test_constraint_required_behavioral() {
    name="gen-lockfile-fails-closed-without-constraint"
    if ! command -v uv >/dev/null 2>&1; then
        pass "$name (skipped: uv not installed)"
        return
    fi
    if [ ! -f "$CONSTRAINT" ]; then
        # Can't run the negative test without a baseline constraint to hide.
        pass "$name (skipped: no constraint file to hide)"
        return
    fi
    make_sandbox
    mkdir -p "$SANDBOX/scripts" "$SANDBOX/agents"
    cp "$GEN" "$SANDBOX/scripts/gen-lockfile.sh"
    [ -f "$UV_VERSION_SH" ] && cp "$UV_VERSION_SH" "$SANDBOX/scripts/uv-version.sh"
    [ -f "$LOCK_DATE" ] && cp "$LOCK_DATE" "$SANDBOX/scripts/lock-date.txt"
    # Copy every agent pyproject (resolver input) preserving layout.
    for pp in "$REPO_ROOT"/agents/*/pyproject.toml; do
        [ -f "$pp" ] || continue
        _d=$(basename "$(dirname "$pp")")
        mkdir -p "$SANDBOX/agents/$_d"
        cp "$pp" "$SANDBOX/agents/$_d/pyproject.toml"
    done
    chmod +x "$SANDBOX/scripts/gen-lockfile.sh"
    # NOTE: deliberately DO NOT copy agents/lockfile-constraints.txt → it is hidden.

    # Run the sandboxed generator; it must FAIL (non-zero) because the constraint
    # is absent. Allow a uv version mismatch so the test exercises the CONSTRAINT
    # check, not the (separate) uv-pin guard.
    if VULTURE_ALLOW_UV_MISMATCH=true sh "$SANDBOX/scripts/gen-lockfile.sh" >/dev/null 2>&1; then
        fail "$name" "gen-lockfile.sh exited 0 with the constraint file absent (M1: must fail closed, exit non-zero)"
    else
        pass "$name"
    fi
}
test_constraint_required_behavioral

# ---------------------------------------------------------------------------
finish
