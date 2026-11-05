#!/usr/bin/env sh
#
# Static guard for the ACTIVE python-build-standalone (PBS) pin — the CPython
# runtime bundled into every native-install tarball.
#
# A PBS bump touches four files that each carry the tag + CPython version
# (build-release.sh, fetch-vendored-pbs.sh, release.yml, vendor-pbs.yml), the
# committed SHA pin, and the attribution docs. A half-done bump ships a runtime
# that the pin, the vendored release, or the license inventory does not
# describe. Asserted:
#   1) all four sources default to the SAME PBS tag and CPython version;
#   2) scripts/pbs-shas-<tag>.txt pins all four triples for exactly that build;
#   3) NOTICE and THIRD_PARTY_LICENSES.md §6 name that build.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() helpers that bump counters, a final "N passed, M failed" line,
# and exit 1 if any case FAILed.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
BUILD="$REPO_ROOT/scripts/build-release.sh"
FETCH="$REPO_ROOT/scripts/fetch-vendored-pbs.sh"
RELEASE="$REPO_ROOT/.github/workflows/release.yml"
VENDOR="$REPO_ROOT/.github/workflows/vendor-pbs.yml"
for _src in "$BUILD" "$FETCH" "$RELEASE" "$VENDOR"; do
    require_file_or_bail "pbs-sources-present" "$_src"
done

# shell_default <file> <VAR> — the value of the first `${VAR:-value}` default.
shell_default() {
    sed -n "s/.*\${$2:-\([^}]*\)}.*/\1/p" "$1" | head -n 1
}

# yaml_env <file> <VAR> — the value of a `VAR: 'value'` env entry.
yaml_env() {
    sed -n "s/^[[:space:]]*$2:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*\$/\1/p" "$1" | head -n 1
}

# input_default <file> <input> — the `default:` of a workflow_dispatch input.
input_default() {
    sed -n "/^[[:space:]]*$2:[[:space:]]*\$/,/default:/s/^[[:space:]]*default:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*\$/\1/p" "$1" | head -n 1
}

# re_escape <text> — <text> with ERE dots escaped (versions are dotted).
re_escape() {
    printf '%s' "$1" | sed 's/[.+]/\\&/g'
}

TAG=$(shell_default "$BUILD" VULTURE_PBS_TAG)
PYVER=$(shell_default "$BUILD" VULTURE_PBS_PYVER)

# ---------------------------------------------------------------------------
# TEST 1 — the four sources agree on the tag and the CPython version.
# ---------------------------------------------------------------------------
# agree <name> <build> <fetch> <release> <vendor> — pass when all four values
# are equal and non-empty.
agree() {
    if [ -n "$2" ] && [ "$2" = "$3" ] && [ "$2" = "$4" ] && [ "$2" = "$5" ]; then
        pass "$1"
    else
        fail "$1" "build-release.sh=$2 fetch-vendored-pbs.sh=$3 release.yml=$4 vendor-pbs.yml=$5"
    fi
}
agree "pbs-tag-agrees" "$TAG" "$(shell_default "$FETCH" VULTURE_PBS_TAG)" \
    "$(yaml_env "$RELEASE" VULTURE_PBS_TAG)" "$(input_default "$VENDOR" pbs_version)"
agree "pbs-pyver-agrees" "$PYVER" "$(shell_default "$FETCH" VULTURE_PBS_PYVER)" \
    "$(yaml_env "$RELEASE" VULTURE_PBS_PYVER)" "$(input_default "$VENDOR" python_version)"

# ---------------------------------------------------------------------------
# TEST 2 — the active pin covers all four triples of exactly this build.
# ---------------------------------------------------------------------------
PIN="$REPO_ROOT/scripts/pbs-shas-$TAG.txt"
require_file_or_bail "active-pin-present" "$PIN"

# pinned <asset> — true when <asset> has a 64-hex SHA-256 line in the pin.
pinned() {
    awk -v f="$1" '$2 == f && length($1) == 64 && $1 !~ /[^0-9a-f]/ { ok = 1 } END { exit !ok }' "$PIN"
}

test_pin_covers_build() {
    missing=
    for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin; do
        pinned "cpython-$PYVER+$TAG-$t-install_only.tar.gz" || missing="$missing $t"
    done
    if [ -z "$missing" ]; then
        pass "active-pin-covers-build"
    else
        fail "active-pin-covers-build" "no SHA for cpython-$PYVER+$TAG on:$missing"
    fi
}
test_pin_covers_build

# ---------------------------------------------------------------------------
# TEST 3 — the attribution docs describe the bundled build.
# ---------------------------------------------------------------------------
PYVER_RE=$(re_escape "$PYVER")
assert_file_matches "third-party-names-build" "$REPO_ROOT/THIRD_PARTY_LICENSES.md" \
    "cpython-$PYVER_RE\\+$TAG" "THIRD_PARTY_LICENSES.md §6 does not name cpython-$PYVER+$TAG"
assert_file_matches "third-party-cpython-row" "$REPO_ROOT/THIRD_PARTY_LICENSES.md" \
    "^\\| CPython \\| $PYVER_RE \\|" "THIRD_PARTY_LICENSES.md §6 CPython row is not $PYVER"
assert_file_matches "notice-names-runtime" "$REPO_ROOT/NOTICE" \
    "$PYVER_RE runtime" "NOTICE does not name the bundled CPython $PYVER runtime"

finish
