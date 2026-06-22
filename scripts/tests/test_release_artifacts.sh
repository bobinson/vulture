#!/usr/bin/env sh
#
# Regression GUARD for the docs-honesty release-artifact checks (C5/C6/C7).
#
# These behaviours ALREADY exist in scripts/build-release.sh (and the committed
# agents/requirements-frozen.txt), so this test is expected to PASS on creation
# — it locks them against silent regression. It is a STATIC test: it greps the
# repo only and never runs a build.
#
#   C5: a committed, non-empty, HASHED frozen lockfile exists, AND
#       build-release.sh COPIES 'requirements-frozen.txt' into the staged tree
#       (so the fail-closed empty-marker branch alone cannot satisfy it).
#   C6: build-release.sh COPIES plugin MANIFESTS (plugin.toml + rules) into
#       runtime/plugins/ and does NOT bundle container images.
#   C7: build-release.sh has a VULTURE_BUNDLE_PBS opt-in path that is
#       env-guarded, downloads a cpython 3.12 install_only PBS tarball,
#       SHA256-verifies it fail-closed against a committed pin (the mismatch
#       comparison block itself exits 1), yields runtime/python/bin/python3.12,
#       and writes a PBS_NOT_BUNDLED marker when the var is unset.
#
# Harness contract: POSIX sh, set -u, pass()/fail() counters, a final
# "N passed, M failed" line, and 'exit 1' if any case FAILed.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

# ---------------------------------------------------------------------------
# Locate the artifacts under test.
# ---------------------------------------------------------------------------
REPO_ROOT=$(repo_root "$0")
BUILD_SH="$REPO_ROOT/scripts/build-release.sh"
FROZEN="$REPO_ROOT/agents/requirements-frozen.txt"

require_file_or_bail "build-release.sh-present" "$BUILD_SH"

# ---------------------------------------------------------------------------
# C5 — committed hashed lockfile + it is COPIED into the tarball.
# ---------------------------------------------------------------------------
test_c5_lockfile_committed() {
    name="C5-frozen-lockfile-committed-hashed"
    if [ ! -s "$FROZEN" ]; then
        fail "$name" "agents/requirements-frozen.txt missing or empty"
        return
    fi
    if grep -q -- '--hash=' "$FROZEN"; then
        pass "$name"
    else
        fail "$name" "agents/requirements-frozen.txt has no --hash= lines (not a hashed lockfile)"
    fi
}
test_c5_lockfile_committed

# The COPY (cp) into runtime/agents — not merely a path mention — must stage the
# lockfile; the fail-closed `: > ...` empty-marker branch must NOT satisfy this.
assert_file_matches \
    "C5-frozen-lockfile-staged-into-tarball" \
    "$BUILD_SH" \
    'cp[[:space:]].*runtime/agents/requirements-frozen\.txt' \
    "build-release.sh does not COPY requirements-frozen.txt into the staged tarball (only the empty-marker branch?)"

# ---------------------------------------------------------------------------
# C6 — plugin MANIFESTS COPIED into runtime/plugins/; no container images.
# ---------------------------------------------------------------------------
test_c6_plugin_manifests() {
    name="C6-plugin-manifests-staged"
    detail=""
    # plugin.toml AND rules must be tied to a copy INTO runtime/plugins, so a
    # stray mention elsewhere cannot stand in for the real staging.
    grep -Eq 'cp .*plugin\.toml.*runtime/plugins' "$BUILD_SH" \
        || detail="$detail plugin.toml not copied into runtime/plugins;"
    grep -Eq 'cp .*rules.*runtime/plugins' "$BUILD_SH" \
        || detail="$detail rule sidecars not copied into runtime/plugins;"
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_c6_plugin_manifests

test_c6_no_images() {
    name="C6-no-container-images-bundled"
    # build-release.sh must NOT pull/save/load/export/build container images.
    if grep -Eq '(docker|podman)[[:space:]]+(pull|save|load|export|build)' "$BUILD_SH"; then
        fail "$name" "build-release.sh bundles container images (docker/podman pull/save/load/export)"
    else
        pass "$name"
    fi
}
test_c6_no_images

# ---------------------------------------------------------------------------
# C7 — VULTURE_BUNDLE_PBS opt-in path.
# ---------------------------------------------------------------------------
assert_file_matches \
    "C7-pbs-env-guarded-opt-in" \
    "$BUILD_SH" \
    'VULTURE_BUNDLE_PBS' \
    "no VULTURE_BUNDLE_PBS env guard for the PBS bundling path"

test_c7_downloads_cpython312() {
    name="C7-downloads-cpython-3.12-install_only"
    detail=""
    grep -Eq 'curl' "$BUILD_SH" \
        || detail="$detail no curl download;"
    grep -Eq 'cpython-' "$BUILD_SH" \
        || detail="$detail no cpython asset reference;"
    grep -Eq 'install_only' "$BUILD_SH" \
        || detail="$detail not the install_only PBS flavour;"
    grep -Eq 'PBS_PYVER.*3\.12' "$BUILD_SH" \
        || detail="$detail PBS python version is not 3.12;"
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_c7_downloads_cpython312

test_c7_sha_failclosed_pin() {
    name="C7-sha256-verify-failclosed-committed-pin"
    detail=""
    # Verifies against a COMMITTED pin file, not the release's own sums.
    grep -Eq 'pbs-shas-' "$BUILD_SH" \
        || detail="$detail no committed pbs-shas pin reference;"
    grep -Eq 'sha256_of' "$BUILD_SH" \
        || detail="$detail no sha256 computation of the downloaded asset;"
    # Fail-closed: the mismatch comparison block ITSELF must 'exit 1'. Slice the
    # `[ "$PBS_EXPECTED" != "$PBS_ACTUAL" ] ... fi` block and require exit 1
    # inside it (not mere -A2 line proximity to the word "mismatch").
    # shellcheck disable=SC2016  # literal $PBS_EXPECTED/$PBS_ACTUAL are matched as text, not expanded
    if sed -n '/PBS_EXPECTED.*!=.*PBS_ACTUAL/,/^[[:space:]]*fi/p' "$BUILD_SH" \
        | grep -Eq 'exit 1'; then :; else
        detail="$detail SHA-mismatch comparison block does not exit 1 (not fail-closed);"
    fi
    # The pin file itself must be committed in the repo.
    ls "$REPO_ROOT"/scripts/pbs-shas-*.txt >/dev/null 2>&1 \
        || detail="$detail no committed scripts/pbs-shas-*.txt pin file;"
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_c7_sha_failclosed_pin

assert_file_matches \
    "C7-yields-runtime-python-bin-python3.12" \
    "$BUILD_SH" \
    'runtime/python/bin/python3\.12' \
    "bundling path does not yield runtime/python/bin/python3.12"

assert_file_matches \
    "C7-PBS_NOT_BUNDLED-marker-when-unset" \
    "$BUILD_SH" \
    'PBS_NOT_BUNDLED' \
    "no PBS_NOT_BUNDLED marker written when VULTURE_BUNDLE_PBS is unset"

# ---------------------------------------------------------------------------
finish
