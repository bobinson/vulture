#!/usr/bin/env sh
#
# Static tests: the release targets three platforms (linux amd64/arm64, darwin
# arm64), and nothing builds, vendors, checks or caps for an Intel Mac.
#
# cryptography ships no Intel macOS wheel after 48.0.1, so while darwin/amd64 was
# a release target the lockfiles capped cryptography at 48.0.1 on macOS, under
# waived advisories. With that target gone, every lockfile pins one cryptography
# for every platform, and the cap and its waivers must not come back on their
# own. install.sh's refusal of an Intel Mac is tested in test_install_sh.sh.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final "N passed, M failed" line, exit 1 on any FAIL.

set -u
# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

ROOT=$(repo_root "$0")
WF="$ROOT/.github/workflows"
LOCKS="agents/requirements-frozen.txt agents/requirements-dev-frozen.txt
mcp/requirements-dev-frozen.txt scripts/requirements-tools-frozen.txt"
INTEL='darwin, arch: amd64|darwin_amd64|darwin-amd64|x86_64-apple-darwin|macos-15-intel'

# absent <name> <ere> <file>... — pass when no line of the files matches, other
# than a whole-line comment (a waiver's reason is a trailing comment, and counts).
absent() {
    name=$1 ere=$2
    shift 2
    hits=$(for f; do grep -nE -- "$ere" "$ROOT/$f" | grep -vE '^[0-9]+:[[:space:]]*#' | sed "s|^|$f:|"; done)
    verdict "$name" "$hits"
}

# --- the release builds and checks three platforms ------------------------------
matrix=$(job_block "$WF/release.yml" build-binary)
detail=""
for leg in 'os: linux, *arch: amd64' 'os: linux, *arch: arm64' 'os: darwin, *arch: arm64'; do
    printf '%s\n' "$matrix" | grep -qE -- "$leg" || detail="$detail no leg '$leg';"
done
verdict "release.yml builds linux amd64/arm64 and darwin arm64" "$detail"

absent "no Intel Mac release leg, runner or digest" "$INTEL" .github/workflows/release.yml

# sign and release refuse anything but one tarball per leg, and per tarball its
# .sig/.pem/.bundle, SBOM and Trivy report, plus SHA256SUMS and its three.
legs=$(printf '%s\n' "$matrix" | grep -cE '^[[:space:]]*- \{ *os: ')
detail=""
for check in "-eq $legs ] || { echo \"want $legs build-leg digests\"" \
             "-eq $legs ] || { echo \"want exactly the $legs tarballs\"" \
             "-eq $legs ] || { echo \"SHA256SUMS must list $legs tarballs\"" \
             "-eq $((6 * legs + 4)) ] || { echo \"want $((6 * legs + 4)) assets\""; do
    grep -qF -- "$check" "$WF/release.yml" || detail="$detail missing: $check;"
done
verdict "sign and release count the $legs build legs' tarballs and assets" "$detail"
absent "no Intel Mac python-build-standalone or cosign is vendored" "$INTEL" \
    .github/workflows/vendor-pbs.yml .github/workflows/vendor-cosign.yml
absent "build-release.sh maps no Intel Mac triple" "$INTEL" scripts/build-release.sh

targets=$(sed -n '/^TARGETS=(/,/^)/p' "$ROOT/scripts/check-lockfile-installable.sh" | grep -cE '^[[:space:]]+[a-z0-9_]+-[a-z]+-[a-z]+')
detail=""
[ "$targets" -eq 3 ] || detail="$targets targets;"
grep -q 'x86_64-apple-darwin' "$ROOT/scripts/check-lockfile-installable.sh" && detail="$detail checks x86_64-apple-darwin;"
verdict "the installability check covers exactly the three release platforms" "$detail"

# --- one cryptography for every platform ----------------------------------------
absent "lockfile-constraints.txt caps no package on macOS" 'sys_platform' agents/lockfile-constraints.txt

detail=""
for lock in $LOCKS; do
    pins=$(grep -E '^cryptography==' "$ROOT/$lock")
    [ -z "$pins" ] && continue
    [ "$(printf '%s\n' "$pins" | wc -l)" -eq 1 ] || detail="$detail $lock pins cryptography per platform;"
    printf '%s' "$pins" | grep -q ';' && detail="$detail $lock gates cryptography on a marker;"
done
verdict "every lockfile pins one cryptography for every platform" "$detail"

absent "no waiver is left for the macOS-only cryptography pin" 'darwin-only' .pip-audit-ignore .trivyignore
absent "gen-lockfile.sh no longer asserts a macOS split" "sys_platform == 'darwin'" scripts/gen-lockfile.sh
absent "the security digest no longer audits a macOS cap" 'darwin-cap' .github/workflows/security-digest.yml

finish
