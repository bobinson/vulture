#!/usr/bin/env sh
# scripts/install-trivy.sh <vX.Y.Z> <bindir> — install the Trivy binary whose
# tarball SHA-256 is committed in scripts/trivy-shas-<vX.Y.Z>.txt (never upstream's
# contrib/install.sh piped into sh). Positional arguments only; reads no environment;
# exits 0 on success, 1 on any refusal (reason on stderr). Bumping: release_process.md.
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/lib/hash.sh
. "$SCRIPT_DIR/lib/hash.sh"

die() { printf 'install-trivy: %s\n' "$*" >&2; exit 1; }

# is_version <s> — exactly vN.N.N (digits); a case pattern sees the whole string, newlines too.
is_version() {
    case $1 in v*[!0-9.]* | v.* | *. | *..* | *.*.*.*) return 1 ;; esac
    case $1 in v*.*.*) return 0 ;; *) return 1 ;; esac
}

# check_args <version> <bindir> — refuse a malformed call before any network.
check_args() {
    [ -n "$2" ] || die "usage: install-trivy.sh <vX.Y.Z> <bindir>"
    is_version "$1" || die "unsupported version '$1'"
    [ -f "$SCRIPT_DIR/trivy-shas-$1.txt" ] || die "no pin file scripts/trivy-shas-$1.txt"
}

# trivy_platform <os> <arch> — upstream's asset token, by table lookup.
trivy_platform() {
    printf '%s\n' 'Linux x86_64 Linux-64bit' 'Linux aarch64 Linux-ARM64' \
        'Darwin x86_64 macOS-64bit' 'Darwin arm64 macOS-ARM64' \
        | awk -v o="$1" -v a="$2" '$1 == o && $2 == a { print $3; f = 1 } END { exit !f }'
}

# fetch_verified <version> <asset> <dest> — download; refuse unless pinned.
fetch_verified() {
    curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 30 --max-time 300 \
        -o "$3" "https://github.com/aquasecurity/trivy/releases/download/$1/$2" || die "download failed for $2"
    sha256_verify_in_sums "$3" "$SCRIPT_DIR/trivy-shas-$1.txt" || die "checksum mismatch for $2"
}

# install_bin <version> <tarball> <bindir> — install only the `trivy` member, iff it reports <version>.
install_bin() {
    _dir=$(dirname "$2")
    tar -xzf "$2" -C "$_dir" trivy || die "cannot extract trivy from ${2##*/}"
    _got=$("$_dir/trivy" --version | sed -n '1s/^Version: //p')
    [ "$_got" = "${1#v}" ] || die "version mismatch: want $1 got $_got"
    mkdir -p "$3"; cp "$_dir/trivy" "$3/trivy"; chmod 0755 "$3/trivy"
}

main() {
    check_args "${1:-}" "${2:-}"
    _os=$(uname -s) _arch=$(uname -m)
    _plat=$(trivy_platform "$_os" "$_arch") || die "unsupported platform $_os/$_arch"
    _asset="trivy_${1#v}_$_plat.tar.gz" _tmp=$(mktemp -d)
    trap 'rm -rf "$_tmp"' EXIT; trap 'exit 1' HUP INT TERM
    fetch_verified "$1" "$_asset" "$_tmp/$_asset"
    install_bin "$1" "$_tmp/$_asset" "$2"
    printf 'install-trivy: installed %s to %s/trivy\n' "$_asset" "$2"
}

main "$@"
