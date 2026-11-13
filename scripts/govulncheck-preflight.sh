#!/usr/bin/env sh
#
# scripts/govulncheck-preflight.sh — pre-tag Go vulnerability gate.
#
# Gate 8 of scripts/release-preflight.sh: govulncheck over every Go module CI's
# `audit-go` job scans, so a reachable vulnerability that turns CI red is caught
# on the laptop before a tag is cut.
#
# Toolchain: govulncheck matches the standard library at the version of the Go
# it runs, so each scan runs under GOTOOLCHAIN=go<V>, V being the go-version
# release.yml builds the shipped binary with, whatever Go is installed locally.
# Another patch adds or hides standard-library CVEs (go1.26.8 reported 13 where
# go1.26.10 reported 1). The go command downloads that toolchain
# when it is missing; the vulnerability DB needs the network anyway.
#
# Exit 1, nothing scanned: release.yml names no go-version, or govulncheck is
# neither on PATH nor where `go install` puts it (GOBIN, else the first GOPATH
# entry's bin): a missing scanner FAILS the gate, never skips it. Exit 1 after
# scanning every module: any module has a reachable vulnerability (govulncheck
# exit 3) or a scan error. Exit 0 otherwise.
#
# POSIX sh, no bashisms. Tiny functions (cyclomatic < 5).
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"
# The modules CI's audit-go job scans (scripts/tests/test_govulncheck_preflight.sh keeps them equal).
MODULES='backend cli'
INSTALL='go install golang.org/x/vuln/cmd/govulncheck@latest'

warn() { printf 'govulncheck-preflight: %s\n' "$*" >&2; }
die() { warn "$@"; exit 1; }

# release_go_version — the first go-version release.yml pins, quoted or not.
release_go_version() {
    sed -n "s/^[[:space:]]*go-version:[[:space:]]*['\"]\{0,1\}\([0-9][0-9.]*\)['\"]\{0,1\}[[:space:]]*$/\1/p" \
        "$RELEASE_YML" | head -n 1
}

# go_install_dir — where `go install` puts a binary: GOBIN, else <first GOPATH entry>/bin.
go_install_dir() {
    command -v go >/dev/null 2>&1 || return 1
    _gobin=$(go env GOBIN) || return 1
    [ -z "$_gobin" ] || { printf '%s\n' "$_gobin"; return 0; }
    _gopath=$(go env GOPATH) || return 1
    printf '%s/bin\n' "${_gopath%%:*}"
}

# find_govulncheck — govulncheck on PATH, else the one `go install` put in its install dir.
find_govulncheck() {
    command -v govulncheck 2>/dev/null && return 0
    _dir=$(go_install_dir) || return 1
    [ -x "$_dir/govulncheck" ] || return 1
    printf '%s\n' "$_dir/govulncheck"
}

# scan <module> — govulncheck <module> under the release toolchain; on a finding or
# an error, report it and return 1 (never exit, so every module is scanned).
scan() {
    echo "    govulncheck $1 (GOTOOLCHAIN=$TOOLCHAIN)"
    _rc=0
    (cd "$REPO_ROOT/$1" && GOTOOLCHAIN=$TOOLCHAIN "$GOVULNCHECK" ./...) || _rc=$?
    case $_rc in
        0) return 0 ;;
        3) warn "$1: reachable vulnerabilities (govulncheck exit 3)" ;;
        *) warn "$1: scan error (govulncheck exit $_rc)" ;;
    esac
    return 1
}

VERSION=$(release_go_version)
[ -n "$VERSION" ] || die "no go-version in $RELEASE_YML: cannot pin the release's Go toolchain"
TOOLCHAIN="go$VERSION"
GOVULNCHECK=$(find_govulncheck) \
    || die "govulncheck not found on PATH, in GOBIN or in GOPATH/bin; install it: $INSTALL"

FAILED=''
for _m in $MODULES; do
    scan "$_m" || FAILED="$FAILED $_m"
done
[ -z "$FAILED" ] || die "failed for:$FAILED. Upgrade the module, or for a standard-library" \
    "finding the Go patch the workflows pin (release.yml, ci.yml), before tagging"
echo "govulncheck-preflight: no reachable vulnerability in $MODULES under $TOOLCHAIN"
