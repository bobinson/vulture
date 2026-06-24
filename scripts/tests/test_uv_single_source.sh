#!/usr/bin/env sh
#
# RED-phase tests for the 0056 "single source of the uv pin" claim (M8).
# Spec: docs/guides/release_hardening_audit.md (M8) +
#       docs/features/0056_release_hardening/0056_implementation_plan.md §10/§13.
#
# The pinned uv version must live in EXACTLY ONE place — scripts/uv-version.sh —
# so bumping uv is a one-line edit. Two consequences are asserted here:
#   1. scripts/uv-version.sh carries the version literal (it is the source).
#   2. The places that previously RE-CITED the literal carry it no longer:
#        - scripts/gen-lockfile.sh sources uv-version.sh (no inline literal);
#        - docs/guides/release_process.md is Markdown prose (not sourceable), so
#          it must DROP the bare version number and refer to the pin by name.
#
# Against the pristine (pre-0056) tree these FAIL (expected RED): gen-lockfile.sh
# inlines UV_VERSION="0.11.21" and release_process.md cites '0.11.21' on ~L31 and
# ~L131. STATIC only; this test asserts the contract, never implements it.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final tally, exit 1 on any FAIL. No bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
UV_VERSION_SH="$REPO_ROOT/scripts/uv-version.sh"
GEN="$REPO_ROOT/scripts/gen-lockfile.sh"
RELEASE_DOC="$REPO_ROOT/docs/guides/release_process.md"

# ---------------------------------------------------------------------------
# TEST 1 (M8) — scripts/uv-version.sh IS the source: it carries a concrete
# UV_VERSION=<x.y.z> assignment. Derive that exact pinned value so the later
# "forbid the literal elsewhere" checks key on the REAL pin (e.g. 0.11.21) and
# stay valid across uv bumps — without false-matching unrelated version numbers
# (e.g. the cryptography==48.0.1 Darwin pin the runbook legitimately cites).
# ---------------------------------------------------------------------------
require_file_or_bail "uv-version-sh-present" "$UV_VERSION_SH"

# UV_PIN — the exact version string uv-version.sh assigns (quotes stripped).
UV_PIN=$(sed -n "s/^[[:space:]]*UV_VERSION=[\"']\{0,1\}\([0-9][0-9.]*\)[\"']\{0,1\}.*/\1/p" \
    "$UV_VERSION_SH" | head -n1)

test_uv_version_carries_literal() {
    name="uv-version-sh-carries-the-literal"
    if [ -n "$UV_PIN" ]; then
        pass "$name"
    else
        fail "$name" "scripts/uv-version.sh has no concrete UV_VERSION=<x.y.z> — it must be the single source of the pin"
    fi
}
test_uv_version_carries_literal

# ---------------------------------------------------------------------------
# TEST 2 (M8) — gen-lockfile.sh carries NO inline uv version literal: neither the
# exact pin nor a `UV_VERSION="<x.y.z>"` assignment. It must SOURCE uv-version.sh
# instead; an inline literal is a second source of truth.
# ---------------------------------------------------------------------------
require_file_or_bail "gen-lockfile-present" "$GEN"
test_gen_has_no_literal() {
    name="gen-lockfile-has-no-uv-version-literal"
    # The exact pin must not appear literally anywhere in the generator …
    if [ -n "$UV_PIN" ] && grep -Fq "$UV_PIN" "$GEN"; then
        fail "$name" "gen-lockfile.sh contains the literal uv pin '$UV_PIN' (must source scripts/uv-version.sh)"
        return
    fi
    # … and no inline UV_VERSION=<x.y.z> assignment of any version may remain.
    if grep -Eq "UV_VERSION=[\"']?[0-9]+\.[0-9]+\.[0-9]+" "$GEN"; then
        fail "$name" "gen-lockfile.sh still inlines a UV_VERSION=\"<x.y.z>\" assignment (must source scripts/uv-version.sh)"
        return
    fi
    pass "$name"
}
test_gen_has_no_literal

# ---------------------------------------------------------------------------
# TEST 3 (M8) — release_process.md contains NO bare uv version literal. The
# runbook is Markdown prose (not sourceable), so it must refer to the pin by
# name ("the uv version pinned in gen-lockfile.sh / scripts/uv-version.sh"),
# never re-cite the number (was on ~L31 + ~L131). Keyed on the EXACT uv pin so
# the unrelated cryptography==48.0.1 pin the doc cites is not a false positive.
# ---------------------------------------------------------------------------
require_file_or_bail "release-doc-present" "$RELEASE_DOC"
test_release_doc_no_literal() {
    name="release-process-md-has-no-uv-version-literal"
    if [ -z "$UV_PIN" ]; then
        fail "$name" "could not derive the uv pin from uv-version.sh; cannot check the doc"
        return
    fi
    _hits=$(grep -nF "$UV_PIN" "$RELEASE_DOC" || true)
    if [ -n "$_hits" ]; then
        _joined=$(printf '%s' "$_hits" | tr '\n' ';')
        fail "$name" "release_process.md still cites the bare uv pin '$UV_PIN' (drop it, name the pin source instead): $_joined"
    else
        pass "$name"
    fi
}
test_release_doc_no_literal

# ---------------------------------------------------------------------------
# TEST 4 (M8) — the runbook NAMES the pin source instead of the number, so the
# dropped literal is replaced by a pointer (not just deleted).
# ---------------------------------------------------------------------------
assert_file_matches \
    "release-process-md-names-the-pin-source" \
    "$RELEASE_DOC" \
    'uv-version\.sh' \
    "release_process.md does not refer to scripts/uv-version.sh as the pin source (it should name the pin, not the number)"

# ---------------------------------------------------------------------------
finish
