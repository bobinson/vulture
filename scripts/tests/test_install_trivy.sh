#!/usr/bin/env sh
#
# Behaviour tests for scripts/install-trivy.sh <vX.Y.Z> <bindir> (feature 0102,
# release supply chain). The script installs a Trivy release binary only when
# the downloaded tarball matches the SHA-256 committed in
# scripts/trivy-shas-<vX.Y.Z>.txt. It reads no environment, exits 0 on success
# and 1 on any refusal, and writes the refusal to stderr.
#
# Hermetic: the script runs from a sandbox copy of scripts/ (its lib/ helpers
# plus a pin file each case writes), with an emptied environment (PATH, HOME,
# TMPDIR) whose PATH puts curl, wget and uname shims first. The curl shim logs
# every call and serves a locally built, upstream-shaped tarball, so nothing
# touches the network.
#
# Cases:
#   ok             exit 0 after one fetch; <bindir> holds only `trivy`, mode
#                  0755, byte-identical to the archive member
#   sha-mismatch   exit 1, "checksum mismatch for <asset>"; nothing installed,
#                  and the downloaded binary never runs
#   missing-pin    a well-formed version without a pin file: exit 1, "no pin
#                  file scripts/trivy-shas-<v>.txt", 0 fetches
#   bad-version    `latest`, `v0.71` and injection-shaped versions: exit 1,
#                  "unsupported version", 0 fetches, no injected command runs
#   url-origin     each platform row fetches exactly the GitHub release asset
#                  <releases>/<v>/trivy_<ver>_<plat>.tar.gz and nothing else;
#                  a platform outside the table fetches nothing
#   wrong-version  the archive's binary reports another version (0.70.0,
#                  0.71.0-dev): exit 1, "version mismatch"
#
# Usage: sh scripts/tests/test_install_trivy.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"
REPO_ROOT=$(repo_root "$0")
# shellcheck source=scripts/lib/hash.sh
. "$REPO_ROOT/scripts/lib/hash.sh"

VERSION=v0.71.0
RELEASES=https://github.com/aquasecurity/trivy/releases/download
# `uname -s`, `uname -m` and upstream's asset token, one platform per line.
PLATFORMS='Linux x86_64 Linux-64bit
Linux aarch64 Linux-ARM64
Darwin x86_64 macOS-64bit
Darwin arm64 macOS-ARM64'

make_sandbox
SB=$SANDBOX
mkdir -p "$SB/repo/scripts" "$SB/payload" "$SB/shims"
cp -R "$REPO_ROOT/scripts/lib" "$SB/repo/scripts/lib"
[ ! -f "$REPO_ROOT/scripts/install-trivy.sh" ] \
    || cp "$REPO_ROOT/scripts/install-trivy.sh" "$SB/repo/scripts/install-trivy.sh"

# fake_tarball <name> <reported version> [extra line] — an upstream-shaped
# archive $SB/payload/<name>.tar.gz whose `trivy` reports <version> for
# --version and touches $SB/ran whenever it is executed.
fake_tarball() {
    _ft="$SB/payload/$1"
    mkdir -p "$_ft/contrib"
    cat > "$_ft/trivy" <<EOF
#!/bin/sh
: > "$SB/ran"
if [ "\${1:-}" = --version ]; then
    printf 'Version: %s\nVulnerability DB:\n  Version: 2\n' '$2'
fi
${3:-}
EOF
    chmod 0755 "$_ft/trivy"
    printf 'license\n' > "$_ft/LICENSE"
    printf 'readme\n' > "$_ft/README.md"
    printf '#!/bin/sh\n' > "$_ft/contrib/install.sh"
    tar -czf "$SB/payload/$1.tar.gz" -C "$_ft" trivy LICENSE README.md contrib
}

# write_shims — curl and wget log each call to $SB/calls.log (curl also logs
# its URLs to $SB/urls.log and writes $SB/serve.tar.gz to its -o/--output
# target, else stdout); wget always fails. uname answers from $SB/platform.
write_shims() {
    cat > "$SB/shims/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$SB/calls.log"
out=""
while [ \$# -gt 0 ]; do
    case \$1 in
        -o|--output) out=\$2; shift ;;
        --output=*) out=\${1#--output=} ;;
        *://*) echo "\$1" >> "$SB/urls.log" ;;
    esac
    shift
done
if [ -n "\$out" ]; then cp "$SB/serve.tar.gz" "\$out"; else cat "$SB/serve.tar.gz"; fi
EOF
    cat > "$SB/shims/wget" <<EOF
#!/bin/sh
echo "wget \$*" >> "$SB/calls.log"
exit 1
EOF
    cat > "$SB/shims/uname" <<EOF
#!/bin/sh
read -r os arch < "$SB/platform"
[ \$# -gt 0 ] || set -- -s
r=""
for a in "\$@"; do
    case \$a in
        -s) r="\$r \$os" ;;
        -m) r="\$r \$arch" ;;
        -sm|-ms) r="\$r \$os \$arch" ;;
    esac
done
echo "\${r# }"
EOF
    chmod 0755 "$SB/shims/curl" "$SB/shims/wget" "$SB/shims/uname"
}

# set_platform <os> <arch> — what the uname shim reports.
set_platform() { printf '%s %s\n' "$1" "$2" > "$SB/platform"; }

# stage <served> <pinned> — curl serves payload <served>; the sandbox pin file
# lists payload <pinned>'s digest for every platform's asset.
stage() {
    cp "$SB/payload/$1.tar.gz" "$SB/serve.tar.gz"
    printf '%s\n' "$PLATFORMS" | awk -v s="$(sha256_of "$SB/payload/$2.tar.gz")" -v v="${VERSION#v}" \
        '{ printf "%s  trivy_%s_%s.tar.gz\n", s, v, $3 }' > "$SB/repo/scripts/trivy-shas-$VERSION.txt"
}

# run_install <version> — run the sandboxed script from a fresh work dir with
# an emptied environment and <bindir> = $SB/work/bin (not created beforehand).
# Sets RC; stdout and stderr land in $SB/out and $SB/err.
run_install() {
    rm -rf "$SB/work" "$SB/tmp" "$SB/ran"
    mkdir -p "$SB/work" "$SB/tmp"
    : > "$SB/calls.log"
    : > "$SB/urls.log"
    (cd "$SB/work" && /usr/bin/env -i PATH="$SB/shims:$PATH" HOME="$SB/work" TMPDIR="$SB/tmp" \
        sh "$SB/repo/scripts/install-trivy.sh" "$1" "$SB/work/bin") > "$SB/out" 2> "$SB/err"
    RC=$?
}

# present <name> — fail <name> and return 1 when the script under test is absent.
present() {
    [ -f "$SB/repo/scripts/install-trivy.sh" ] && return 0
    fail "$1" "scripts/install-trivy.sh is missing"
    return 1
}

net_calls() { wc -l < "$SB/calls.log" | tr -d ' '; }

# expect_exit <rc> <stderr text> — detail unless the run exited <rc> and, when
# <stderr text> is non-empty, its stderr contains it.
expect_exit() {
    [ "$RC" -eq "$1" ] || printf ' exit %s, want %s;' "$RC" "$1"
    [ -z "$2" ] || grep -Fq -- "$2" "$SB/err" \
        || printf ' stderr lacks "%s" (got: %s);' "$2" "$(head -c 200 "$SB/err" | tr '\n' ' ')"
}

# expect_fetches <n> — detail unless curl/wget ran exactly <n> times.
expect_fetches() {
    _n=$(net_calls)
    [ "$_n" -eq "$1" ] || printf ' %s network call(s), want %s;' "$_n" "$1"
}

# expect_not_installed — detail when trivy landed in <bindir> or ever ran.
expect_not_installed() {
    [ ! -e "$SB/work/bin/trivy" ] || printf ' trivy was installed;'
    [ ! -e "$SB/ran" ] || printf ' the downloaded binary was executed;'
}

# expect_installed <payload> — detail unless <bindir> holds only `trivy`, mode
# 0755, byte-identical to <payload>'s archive member.
expect_installed() {
    _bin="$SB/work/bin"
    [ -z "$(find "$_bin" -mindepth 1 ! -name trivy 2>/dev/null)" ] || printf ' bindir holds more than trivy;'
    [ -n "$(find "$_bin/trivy" -prune -perm 0755 2>/dev/null)" ] || printf ' no trivy with mode 0755 in bindir;'
    cmp -s "$SB/payload/$1/trivy" "$_bin/trivy" || printf ' installed trivy is not the archive member;'
}

# fetch_detail <os> <arch> <plat> — detail unless an install on <os>/<arch>
# succeeds after one fetch of exactly the <plat> release asset.
fetch_detail() {
    set_platform "$1" "$2"
    run_install "$VERSION"
    _want="$RELEASES/$VERSION/trivy_${VERSION#v}_$3.tar.gz"
    _got=$(tr '\n' ' ' < "$SB/urls.log")
    [ "$_got" = "$_want " ] || printf ' %s/%s fetched [%s], want [%s];' "$1" "$2" "$_got" "$_want"
    _fd="$(expect_exit 0 '')$(expect_fetches 1)"
    [ -z "$_fd" ] || printf ' %s/%s:%s' "$1" "$2" "$_fd"
}

case_ok() {
    present ok || return 0
    set_platform Linux x86_64
    stage good good
    run_install "$VERSION"
    verdict ok "$(expect_exit 0 '')$(expect_fetches 1)$(expect_installed good)"
}

case_sha_mismatch() {
    present sha-mismatch || return 0
    set_platform Linux x86_64
    stage tampered good
    run_install "$VERSION"
    verdict sha-mismatch "$(expect_exit 1 "install-trivy: checksum mismatch for trivy_${VERSION#v}_Linux-64bit.tar.gz")$(expect_fetches 1)$(expect_not_installed)"
}

case_missing_pin() {
    present missing-pin || return 0
    set_platform Linux x86_64
    stage good good
    run_install v0.70.0
    verdict missing-pin "$(expect_exit 1 'install-trivy: no pin file scripts/trivy-shas-v0.70.0.txt')$(expect_fetches 0)$(expect_not_installed)"
}

case_bad_version() {
    present bad-version || return 0
    set_platform Linux x86_64
    stage good good
    _d=""
    # shellcheck disable=SC2016 # the $(...) sample is literal text, not an expansion
    for _v in latest v0.71 0.71.0 '' "v0.71.0;touch $SB/pwned" "\$(touch $SB/pwned)" \
              'v0.71.0/../../x' "$(printf 'v0.71.0\nv0.71.0')"; do
        run_install "$_v"
        _r="$(expect_exit 1 'install-trivy: unsupported version')$(expect_fetches 0)$(expect_not_installed)"
        [ -z "$_r" ] || _d="$_d [$_v]$_r"
    done
    [ ! -e "$SB/pwned" ] || _d="$_d an injected command ran;"
    verdict bad-version "$_d"
}

case_url_origin() {
    present url-origin || return 0
    stage good good
    _d=$(printf '%s\n' "$PLATFORMS" | while read -r _os _arch _plat; do fetch_detail "$_os" "$_arch" "$_plat"; done)
    set_platform FreeBSD amd64
    run_install "$VERSION"
    verdict url-origin "$_d$(expect_exit 1 'install-trivy: unsupported platform FreeBSD/amd64')$(expect_fetches 0)"
}

case_wrong_version() {
    present wrong-version || return 0
    set_platform Linux x86_64
    _d=""
    for _p in v0700 v071dev; do
        stage "$_p" "$_p"
        run_install "$VERSION"
        _r="$(expect_exit 1 'install-trivy: version mismatch')$(expect_fetches 1)"
        [ -z "$_r" ] || _d="$_d [$_p]$_r"
    done
    verdict wrong-version "$_d"
}

fake_tarball good 0.71.0
fake_tarball tampered 0.71.0 '# tampered'
fake_tarball v0700 0.70.0
fake_tarball v071dev 0.71.0-dev
write_shims

case_ok
case_sha_mismatch
case_missing_pin
case_bad_version
case_url_origin
case_wrong_version
finish
