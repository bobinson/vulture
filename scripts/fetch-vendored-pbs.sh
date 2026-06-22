#!/usr/bin/env sh
#
# scripts/fetch-vendored-pbs.sh — download the cosign-signed, vendored
# python-build-standalone (PBS) tarball for one platform and verify its
# signature BEFORE the release build bundles it (feature 0044 S9).
#
# This is the consume side of vendor-pbs.yml: that workflow re-hosts the
# upstream PBS tarballs under the `vendor-pbs-<tag>` release and cosign-signs
# the aggregate SHA256SUMS (keyless/OIDC). Here we fetch the platform tarball +
# SHA256SUMS{,.sig,.pem}, cosign-verify the sums, then confirm the tarball's
# digest is one the verified sums vouches for. On success we print the verified
# tarball's absolute path on stdout so release.yml can pass it to
# build-release.sh via VULTURE_PBS_TARBALL.
#
# Usage:
#   scripts/fetch-vendored-pbs.sh <os> <arch> <dest-dir>
#
# Env (defaults mirror build-release.sh so the fetched asset matches the pin):
#   VULTURE_PBS_TAG          PBS upstream tag    (default 20260610)
#   VULTURE_PBS_PYVER        CPython version     (default 3.12.13)
#   VULTURE_PBS_VENDOR_REPO  GitHub repo hosting the VENDORED (re-hosted) PBS
#                            release we consume here — NOT upstream indygreg
#                            (default $GITHUB_REPOSITORY, else bobinson/vulture)
#   GH_TOKEN                 token for `gh release download` (set by the workflow)
#
# POSIX sh, no bashisms; shellcheck-clean.

set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/hash.sh disable=SC1091
. "$REPO_ROOT/scripts/lib/hash.sh"

OS=${1:?usage: fetch-vendored-pbs.sh <os> <arch> <dest-dir>}
ARCH=${2:?usage: fetch-vendored-pbs.sh <os> <arch> <dest-dir>}
DEST=${3:?usage: fetch-vendored-pbs.sh <os> <arch> <dest-dir>}

# Required tools: gh (to download the vendored release) and cosign (to verify its
# keyless signature). Check BOTH up front so a missing tool fails LOUDLY with a
# clear message instead of an opaque "command not found" mid-pipeline.
for _tool in gh cosign; do
    command -v "$_tool" >/dev/null 2>&1 || {
        echo "error: required tool '$_tool' not found on PATH" \
             "(need 'gh' to download the vendored PBS release and 'cosign' to verify it)" >&2
        exit 1
    }
done

PBS_TAG=${VULTURE_PBS_TAG:-20260610}
PBS_PYVER=${VULTURE_PBS_PYVER:-3.12.13}
# VENDOR repo = our own re-hosted PBS release (vendor-pbs.yml), NOT upstream
# indygreg. build-release.sh's separate VULTURE_PBS_UPSTREAM_REPO means upstream.
VENDOR_REPO=${VULTURE_PBS_VENDOR_REPO:-${GITHUB_REPOSITORY:-bobinson/vulture}}
VENDOR_TAG="vendor-pbs-${PBS_TAG}"
# The vendor pipeline renames each tarball to its <os>-<arch> platform form.
ASSET="cpython-${PBS_PYVER}+${PBS_TAG}-${OS}-${ARCH}-install_only.tar.gz"

mkdir -p "$DEST"

# Pull the platform tarball plus the signed checksum bundle from our own
# vendored release (NOT upstream indygreg).
gh release download "$VENDOR_TAG" --repo "$VENDOR_REPO" --dir "$DEST" --clobber \
    --pattern "$ASSET" \
    --pattern "SHA256SUMS" \
    --pattern "SHA256SUMS.sig" \
    --pattern "SHA256SUMS.pem"

# Keyless cosign verification of the aggregate SHA256SUMS. The signing identity
# is the vendor-pbs workflow on this repo; the issuer is GitHub's OIDC provider.
cosign verify-blob "$DEST/SHA256SUMS" \
    --signature "$DEST/SHA256SUMS.sig" \
    --certificate "$DEST/SHA256SUMS.pem" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp "^https://github.com/${VENDOR_REPO}/\.github/workflows/vendor-pbs\.yml@" \
    >&2

# Confirm the downloaded tarball is one the verified sums vouches for. Run from
# $DEST so the basename in SHA256SUMS resolves to the just-downloaded file; the
# helper is fail-closed (non-zero on mismatch or a missing basename line) and
# uses the same sha256sum/shasum portability as the rest of the pipeline.
( cd "$DEST" && sha256_verify_in_sums "$ASSET" SHA256SUMS ) >&2

printf '%s/%s\n' "$DEST" "$ASSET"
