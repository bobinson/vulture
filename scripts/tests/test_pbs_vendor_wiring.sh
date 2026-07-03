#!/usr/bin/env sh
#
# RED-phase static tests for pending item #2:
#   "cosign-signed PBS vendor pipeline wired into release".
#
# These tests are STATIC: they read the committed YAML + shell sources and
# assert structural facts about how the python-build-standalone (PBS) vendor
# pipeline is wired. They do NOT execute GitHub Actions (that is CI-only and
# out of scope). They assert ONLY the desired end-state, never implementing it.
#
# Asserted contract:
#   1) PIN-FILE NAME CONSISTENCY — .github/workflows/vendor-pbs.yml and
#      scripts/build-release.sh must reference the SAME committed PBS SHA pin
#      file. Today vendor-pbs.yml references scripts/pbs-shas.txt while
#      build-release.sh references scripts/pbs-shas-<tag>.txt — a mismatch this
#      test must catch.
#   2) COSIGN SIGNING — vendor-pbs.yml must cosign-sign the vendored PBS
#      artifacts it publishes.
#   3) RELEASE CONSUMES VENDORED PBS — release.yml must consume the vendored
#      (signed) PBS artifact for its bundling step instead of fetching directly
#      from indygreg at build time.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() helpers that bump counters, a final "N passed, M failed" line,
# and exit 1 if any case FAILed.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

# ---------------------------------------------------------------------------
# Source files under test.
# ---------------------------------------------------------------------------
REPO_ROOT=$(repo_root "$0")
VENDOR_YML="$REPO_ROOT/.github/workflows/vendor-pbs.yml"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"
BUILD_SH="$REPO_ROOT/scripts/build-release.sh"
PIN_FILE="$REPO_ROOT/scripts/pbs-shas-20260610.txt"

# ---------------------------------------------------------------------------
# pin_forms <file> — print the DISTINCT pin-file basename forms referenced in
# <file>, one per line. Interpolations (GitHub ${{ ... }} and shell ${...}) are
# normalised to a single <TAG> placeholder so per-tool variable names don't
# create spurious differences; only the structural shape survives.
# ---------------------------------------------------------------------------
pin_forms() {
    grep -oE 'pbs-shas[^ ":'"'"']*\.txt' "$1" 2>/dev/null \
        | sed -e 's/\${{[^}]*}}/<TAG>/g' -e 's/\${[^}]*}/<TAG>/g' \
              -e 's/<[Tt][Aa][Gg]>/<TAG>/g' \
        | sort -u
}

# ---------------------------------------------------------------------------
# TEST 1 — pin-file name consistency.
# The union of pin-file forms referenced across vendor-pbs.yml and
# build-release.sh must collapse to EXACTLY ONE form. Today vendor-pbs.yml
# carries both `pbs-shas.txt` and `pbs-shas-<tag>.txt` while build-release.sh
# uses `pbs-shas-<tag>.txt`, so the union has >1 form -> RED.
# ---------------------------------------------------------------------------
test_pin_consistency() {
    name="pin-file-name-consistency"
    require_file_or_bail "$name" "$VENDOR_YML"
    require_file_or_bail "$name" "$BUILD_SH"
    forms=$( { pin_forms "$VENDOR_YML"; pin_forms "$BUILD_SH"; } | sort -u )
    n=$(printf '%s\n' "$forms" | grep -c .)
    if [ "$n" -eq 1 ]; then
        pass "$name"
    else
        joined=$(printf '%s' "$forms" | tr '\n' ',' )
        fail "$name" "vendor-pbs.yml and build-release.sh reference $n distinct PBS pin-file forms (want 1): $joined"
    fi
}
test_pin_consistency

# ---------------------------------------------------------------------------
# TEST 2 — vendor-pbs.yml cosign-signs the vendored PBS artifacts.
# A real signing step invokes cosign on the published artifacts (sign-blob over
# the tarballs/SHA256SUMS, or sign over the release). Today vendor-pbs.yml has
# no cosign step at all -> RED.
# ---------------------------------------------------------------------------
test_vendor_cosign_signs() {
    name="vendor-pbs-cosign-signs"
    require_file_or_bail "$name" "$VENDOR_YML"
    if grep -q 'cosign' "$VENDOR_YML" \
       && grep -Eq 'cosign[[:space:]]+(sign-blob|sign)' "$VENDOR_YML"; then
        pass "$name"
    else
        fail "$name" "vendor-pbs.yml does not cosign-sign the vendored PBS artifacts (no 'cosign sign-blob'/'cosign sign' step)"
    fi
}
test_vendor_cosign_signs

# ---------------------------------------------------------------------------
# TEST 3 — release.yml consumes the vendored (signed) PBS artifact.
# The bundling step must pull PBS from our own vendored release (vendor-pbs-*)
# rather than fetching from indygreg at build time. Today PBS is fetched
# straight from indygreg inside build-release.sh (called by release.yml) and
# release.yml never references the vendor pipeline -> RED.
#
# Pass requires BOTH:
#   (a) release.yml references the vendored PBS source (e.g. a vendor-pbs-*
#       release tag, VULTURE_PBS_REPO pointing at our own repo, or a
#       download-artifact of the pbs-* vendor artifacts), AND
#   (b) the build-time path no longer hardcodes a direct indygreg fetch.
# ---------------------------------------------------------------------------
test_release_consumes_vendored() {
    name="release-consumes-vendored-pbs"
    require_file_or_bail "$name" "$RELEASE_YML"
    require_file_or_bail "$name" "$BUILD_SH"
    detail=""
    grep -Eq 'vendor-pbs|VULTURE_PBS_REPO|VULTURE_PBS_BASE|pbs-(linux|darwin|amd64|arm64)|download-artifact.*pbs' "$RELEASE_YML" \
        || detail="$detail release.yml never references the vendored PBS artifact/repo;"
    # shellcheck disable=SC2016  # literal ${PBS_REPO}/${PBS_TAG} are matched as text in a grep PATTERN, not expanded
    if grep -q 'indygreg/python-build-standalone' "$BUILD_SH" \
       && grep -Eq 'github\.com/\$\{PBS_REPO\}|releases/download/\$\{PBS_TAG\}' "$BUILD_SH"; then
        detail="$detail build-time bundling still fetches PBS directly from indygreg;"
    fi
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_release_consumes_vendored

# ---------------------------------------------------------------------------
# TEST 4 — vendor-pbs.yml's SHA-lookup key RESOLVES against the committed pin.
# Column 2 of scripts/pbs-shas-<tag>.txt is the FULL upstream asset filename
# (cpython-<pyver>+<tag>-<triple>-install_only.tar.gz), so the workflow MUST key
# its `awk '$2==KEY'` lookup on that asset name — NOT the bare triple. We read
# the key the WORKFLOW builds (its `ASSET=` line), expand it per triple using
# pyver/tag from the committed pin, and assert it resolves a non-empty SHA for
# ALL FOUR triples. The OLD workflow keyed on the bare triple
# (`awk -v t="...matrix.triple..." '$2==t'`), which resolves EMPTY for every
# triple (column 2 is never a bare triple) so the verify step exits 1 — this
# case FAILs there and PASSes once B1 keys on the full asset name.
# ---------------------------------------------------------------------------
TRIPLES='x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin'

# resolve_key <asset-key> — print the SHA the pin lists for <asset-key> via the
# SAME exact-field match the workflow uses (awk '$2==key'); empty if none.
resolve_key() {
    awk -v f="$1" '$2==f {print $1}' "$PIN_FILE"
}

# workflow_asset_template — extract the RHS of the workflow's `ASSET=...` line
# (its SHA-lookup key) with the surrounding quotes stripped. Empty if the
# workflow never builds a full asset-name key (e.g. the old bare-triple form).
workflow_asset_template() {
    sed -n 's/^[[:space:]]*ASSET=//p' "$VENDOR_YML" | head -n1 | sed 's/^"//; s/"$//'
}

# expand_template <template> <pyver> <tag> <triple> — substitute the workflow's
# GitHub expressions in the asset template with concrete values.
expand_template() {
    printf '%s' "$1" \
        | sed -e "s/\${{ inputs.python_version }}/$2/g" \
              -e "s/\${{ inputs.pbs_version }}/$3/g" \
              -e "s/\${{ matrix.triple }}/$4/g"
}

test_vendor_pin_resolves() {
    name="vendor-pin-key-resolves-all-triples"
    require_file_or_bail "$name" "$PIN_FILE"
    require_file_or_bail "$name" "$VENDOR_YML"
    detail=""
    # The workflow must build a FULL asset-name key (the B1 fix), not a bare triple.
    tmpl=$(workflow_asset_template)
    case "$tmpl" in
        cpython-*install_only.tar.gz) : ;;
        *) detail="$detail vendor-pbs.yml builds no full asset-name SHA key (ASSET= line is '$tmpl' — bare-triple/B1-unfixed);" ;;
    esac
    # The OLD bare-triple key must be GONE from the verify step.
    if grep -Eq "awk -v t=\"\\\$\{\{ matrix.triple \}\}\"" "$VENDOR_YML" \
       || grep -Eq "awk -v t=\"\\\$\{ *matrix.triple *\}\"" "$VENDOR_YML"; then
        detail="$detail vendor-pbs.yml still keys awk on the bare \${{ matrix.triple }} (B1 not fixed);"
    fi
    # Derive pyver+tag from the pin's first asset filename and confirm the
    # workflow's expanded key resolves non-empty for every triple.
    _first=$(awk 'NF>=2 {print $2; exit}' "$PIN_FILE")
    _pyver=$(printf '%s' "$_first" | sed -n 's/^cpython-\([^+]*\)+.*/\1/p')
    _tag=$(printf '%s' "$_first" | sed -n 's/^cpython-[^+]*+\([0-9][0-9]*\)-.*/\1/p')
    [ -n "$_pyver" ] && [ -n "$_tag" ] \
        || detail="$detail could not parse pyver/tag from pin entry '$_first';"
    if [ -n "$tmpl" ] && [ -n "$_pyver" ] && [ -n "$_tag" ]; then
        for t in $TRIPLES; do
            _asset=$(expand_template "$tmpl" "$_pyver" "$_tag" "$t")
            [ -n "$(resolve_key "$_asset")" ] \
                || detail="$detail workflow key for $t ('$_asset') resolved EMPTY against the pin;"
        done
    fi
    # Negative guard: the BARE-triple key (the B1 bug) must resolve EMPTY — proving
    # this case genuinely discriminates the fixed key from the broken one.
    for t in $TRIPLES; do
        [ -z "$(resolve_key "$t")" ] \
            || detail="$detail bare-triple key for $t unexpectedly resolved (pin column 2 is not a bare triple);"
    done
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_vendor_pin_resolves

# ---------------------------------------------------------------------------
# Tally + non-zero exit on any failure.
# ---------------------------------------------------------------------------
finish
