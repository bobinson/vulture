#!/usr/bin/env sh
#
# RED-phase static tests for pending item #1 — darwin + arm64 PBS bundling.
#
# These tests assert the DESIRED multi-platform behaviour of the
# VULTURE_BUNDLE_PBS pipeline; they do NOT implement it.  Two artefacts are
# under test:
#
#   scripts/pbs-shas-20260610.txt   — must pin SHAs for ALL FOUR PBS triples.
#   scripts/build-release.sh        — must DERIVE the PBS triple from (os,arch)
#                                     for all four platforms and must NOT gate
#                                     bundling SOLELY on a linux+amd64
#                                     conjunction (which ships PBS_NOT_BUNDLED
#                                     for every other platform).
#
# Today only the linux/amd64 triple is pinned, the triple is hardcoded, and the
# amd64-only conjunction guard exists, so this whole suite FAILs (expected RED).
# The real cross-platform RUN (fetch/extract/pip on Mac + arm64 CI runners) is
# verified later and is out of scope for this static unit test.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() helpers that bump counters, a final "N passed, M failed" line,
# and exit 1 if any case FAILed.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
PIN="$REPO_ROOT/scripts/pbs-shas-20260610.txt"
BUILD="$REPO_ROOT/scripts/build-release.sh"

# Both artefacts must exist for ANY case to be meaningful — bail once up front
# rather than re-checking inside every function.
require_file_or_bail "pin-file-present" "$PIN"
require_file_or_bail "build-release.sh-present" "$BUILD"

# The four PBS triples the installer must support, one per host platform.
TRIPLES='x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin'

# Slurp each file ONCE; membership is tested with `case` (no per-iteration grep).
PIN_DATA=$(cat "$PIN")
BUILD_DATA=$(cat "$BUILD")

# The bundling block (where PBS_TRIPLE is set). A multi-platform fix derives the
# triple from $OS/$ARCH HERE, so we slurp it once and assert on the positive
# end-state. Tolerant of quotes/braces/[[ in the eventual derivation.
# shellcheck disable=SC2016  # literal $_bundle_pbs is matched as text in the sed address, not expanded
BUNDLE_BLOCK=$(sed -n '/if \[ *"\{0,1\}\$_bundle_pbs"\{0,1\} *= *1 *\]/,/^[[:space:]]*else/p' "$BUILD")

# triple_in <haystack> <triple> — membership via case glob, no grep.
triple_in() {
    case "$1" in
        *"$2"*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# TEST 1 — the SHA pin file lists ALL FOUR triples.
# ---------------------------------------------------------------------------
test_pin_all_triples() {
    missing=
    for t in $TRIPLES; do
        triple_in "$PIN_DATA" "$t" || missing="$missing $t"
    done
    if [ -z "$missing" ]; then
        pass "pin-all-four-triples"
    else
        fail "pin-all-four-triples" "no SHA pin for:$missing"
    fi
}
test_pin_all_triples

# ---------------------------------------------------------------------------
# TEST 2 — build-release.sh references every platform's PBS triple.
# ---------------------------------------------------------------------------
test_build_maps_all_triples() {
    missing=
    for t in $TRIPLES; do
        triple_in "$BUILD_DATA" "$t" || missing="$missing $t"
    done
    if [ -z "$missing" ]; then
        pass "build-maps-all-triples"
    else
        fail "build-maps-all-triples" "build-release.sh maps no triple for:$missing"
    fi
}
test_build_maps_all_triples

# ---------------------------------------------------------------------------
# TEST 3 — POSITIVE end-state: the triple is DERIVED from (os,arch) inside the
# bundling block AND bundling is no longer gated SOLELY on a linux+amd64
# conjunction. (Replaces the old brittle, single-space-only negative grep.)
#   (a) the bundling block references BOTH PBS_TRIPLE and $ARCH/$OS — i.e. the
#       triple is selected per platform, not hardcoded to one literal; AND
#   (b) the spacing/quote/[[-tolerant `[ "$OS" = linux ] && [ "$ARCH" = amd64 ]`
#       conjunction no longer appears.
# Today (a) is false (the block has no $ARCH/$OS) and (b) is false (the guard is
# present), so this FAILs (RED).
# ---------------------------------------------------------------------------
test_triple_derived_not_amd64_only() {
    name="no-amd64-only-guard"
    detail=""
    if printf '%s\n' "$BUNDLE_BLOCK" | grep -q 'PBS_TRIPLE' \
        && printf '%s\n' "$BUNDLE_BLOCK" | grep -Eq '\$\{?(ARCH|OS)\}?'; then :; else
        detail="$detail PBS_TRIPLE not derived from \$OS/\$ARCH in the bundling block;"
    fi
    # Spacing/quote/[[-tolerant linux+amd64 conjunction. Its presence means
    # bundling is still hard-restricted to one platform.
    # shellcheck disable=SC2016  # literal $OS/$ARCH are matched as text in a grep PATTERN, not expanded
    _conj='\[\[?[[:space:]]*"?\$\{?OS\}?"?[[:space:]]*=[[:space:]]*"?linux"?[[:space:]]*\]\]?[[:space:]]*&&[[:space:]]*\[\[?[[:space:]]*"?\$\{?ARCH\}?"?[[:space:]]*=[[:space:]]*"?amd64'
    if grep -Eq "$_conj" "$BUILD"; then
        detail="$detail linux/amd64-only bundling conjunction still present (PBS hard-restricted to one platform);"
    fi
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_triple_derived_not_amd64_only

# ---------------------------------------------------------------------------
# TEST 4 — PBS_TRIPLE is DERIVED from (os,arch), not a single hardcoded literal.
# A multi-platform build selects the triple per platform; a lone literal
# assignment with no $OS/$ARCH anywhere in the bundling block is the
# single-platform tell. (Replaces the exact-literal absence check.)
# ---------------------------------------------------------------------------
test_triple_derived() {
    name="triple-not-hardcoded"
    if printf '%s\n' "$BUNDLE_BLOCK" | grep -q 'PBS_TRIPLE' \
        && printf '%s\n' "$BUNDLE_BLOCK" | grep -Eq '\$\{?(ARCH|OS)\}?'; then
        pass "$name"
    else
        fail "$name" "PBS_TRIPLE is not derived from \$OS/\$ARCH (hardcoded to one platform — no per-platform mapping)"
    fi
}
test_triple_derived

finish
