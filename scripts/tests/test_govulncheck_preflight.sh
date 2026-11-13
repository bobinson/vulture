#!/usr/bin/env sh
#
# Behaviour tests for scripts/govulncheck-preflight.sh — the release preflight's
# Go vulnerability gate (scripts/release-preflight.sh, gate 8).
#
# Contract:
#   - govulncheck runs over every Go module CI's `audit-go` job scans, each from
#     its own directory with `./...`; a clean scan of all of them exits 0.
#   - It runs under GOTOOLCHAIN=go<V>, V the go-version release.yml's
#     build-binary job pins, whatever GOTOOLCHAIN the caller has: govulncheck
#     matches the standard library at the running Go's version, so only the
#     release's Go predicts the shipped binary's verdict.
#   - A reachable vulnerability (govulncheck exit 3) or a scan error (any other
#     non-zero) fails the gate, names the module, and does not stop the other
#     modules from being scanned.
#   - govulncheck is found on PATH, else where `go install` puts it (GOBIN, else
#     the first GOPATH entry's bin). Absent everywhere: the gate FAILS with the
#     install command, never skips (as security-preflight.sh does for pip-audit).
#   - No go-version in release.yml: the gate fails without scanning.
#
# Hermetic: the gate runs from a copy in a sandbox repo with a fake `go` and a
# fake `govulncheck` on a PATH holding nothing else but a few host utilities, so
# a govulncheck installed on the host can never leak in. The last two cases run
# the real script in the real repo (still with the fakes) to tie it to the real
# release.yml and ci.yml.
#
# Harness contract (scripts/tests/lib.sh): POSIX sh, set -u, pass()/fail(),
# finish() tally, exit 1 on any FAIL. Tiny functions, no bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
GATE="$REPO_ROOT/scripts/govulncheck-preflight.sh"
SH=$(command -v sh)

make_sandbox
require_file_or_bail "govulncheck-preflight.sh-present" "$GATE"

FAKE_VERSION='1.99.7'
REPO="$SANDBOX/repo"
LOG="$SANDBOX/govulncheck.log"
OUT="$SANDBOX/out"
BIN="$SANDBOX/bin"
TOOLS="$SANDBOX/tools"

# The host utilities the gate may use; nothing else is reachable on its PATH.
mkdir -p "$TOOLS"
for _t in dirname sed head cat tr grep awk basename; do
    _p=$(command -v "$_t") && ln -s "$_p" "$TOOLS/$_t"
done

# new_repo <release.yml body> — a sandbox repo holding a copy of the gate, the
# given release.yml, and empty backend/ and cli/ module dirs.
new_repo() {
    rm -rf "$REPO"
    mkdir -p "$REPO/scripts" "$REPO/.github/workflows" "$REPO/backend" "$REPO/cli"
    cp "$GATE" "$REPO/scripts/"
    printf '%s\n' "$1" > "$REPO/.github/workflows/release.yml"
}

RELEASE_YML="jobs:
  build-binary:
    steps:
      - uses: actions/setup-go@0000000000000000000000000000000000000000 # v7
        with:
          go-version: '$FAKE_VERSION'"

# reset — a fresh fake-tool dir, an empty scan log, and no forced exit codes.
reset() {
    rm -rf "$BIN" "$SANDBOX/gopath" "$SANDBOX/gobin" "$LOG" "$SANDBOX"/rc.*
    mkdir -p "$BIN"
    : > "$LOG"
}

# write_govulncheck <dir> — a fake govulncheck in <dir>. It logs
# "<module dir>|<GOTOOLCHAIN>|<args>" and exits with the code in rc.<module dir>
# when that file exists, else 0.
write_govulncheck() {
    mkdir -p "$1"
    cat > "$1/govulncheck" <<EOF
#!/bin/sh
printf '%s|%s|%s\n' "\${PWD##*/}" "\${GOTOOLCHAIN-}" "\$*" >> "$LOG"
if [ -f "$SANDBOX/rc.\${PWD##*/}" ]; then read -r rc < "$SANDBOX/rc.\${PWD##*/}"; exit "\$rc"; fi
exit 0
EOF
    chmod +x "$1/govulncheck"
}

# write_go <gobin> — a fake go answering `go env GOBIN` with <gobin> and
# `go env GOPATH` with a two-entry list whose first entry is $SANDBOX/gopath.
write_go() {
    cat > "$BIN/go" <<EOF
#!/bin/sh
case "\$*" in
    'env GOBIN') printf '%s\n' '$1' ;;
    'env GOPATH') printf '%s\n' '$SANDBOX/gopath:$SANDBOX/gopath2' ;;
    *) exit 2 ;;
esac
EOF
    chmod +x "$BIN/go"
}

# run_gate <repo> — run <repo>'s gate with the hermetic PATH and a caller
# GOTOOLCHAIN of `local`; output to $OUT, exit code echoed.
run_gate() {
    (
        PATH="$BIN:$TOOLS"
        GOTOOLCHAIN=local
        export PATH GOTOOLCHAIN
        "$SH" "$1/scripts/govulncheck-preflight.sh"
    ) > "$OUT" 2>&1
    echo $?
}

# scanned — the module dirs the fake govulncheck ran in, sorted, one per line.
scanned() { sed 's/|.*//' "$LOG" | sort; }

out() { tr '\n' ' ' < "$OUT"; }

# ---------------------------------------------------------------------------
test_clean_passes() {
    name="clean-scan-of-every-module-passes"
    new_repo "$RELEASE_YML"; reset; write_go ''; write_govulncheck "$BIN"
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -eq 0 ] || d="$d exit $rc on a clean scan (want 0): $(out);"
    grep -qx 'backend|[^|]*|\./\.\.\.' "$LOG" || d="$d backend not scanned with ./...;"
    grep -qx 'cli|[^|]*|\./\.\.\.' "$LOG" || d="$d cli not scanned with ./...;"
    verdict "$name" "$d"
}
test_clean_passes

test_release_toolchain() {
    name="scans-under-the-release-go-toolchain-not-the-callers"
    new_repo "$RELEASE_YML"; reset; write_go ''; write_govulncheck "$BIN"
    run_gate "$REPO" >/dev/null
    d=""
    [ -s "$LOG" ] || d="$d govulncheck never ran: $(out);"
    ! grep -v "^[^|]*|go$FAKE_VERSION|" "$LOG" | grep -q . \
        || d="$d a scan ran without GOTOOLCHAIN=go$FAKE_VERSION: $(tr '\n' ' ' < "$LOG");"
    verdict "$name" "$d"
}
test_release_toolchain

test_vuln_fails_and_scans_rest() {
    name="reachable-vulnerability-fails-names-module-and-scans-the-rest"
    new_repo "$RELEASE_YML"; reset; write_go ''; write_govulncheck "$BIN"
    echo 3 > "$SANDBOX/rc.backend"
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -ne 0 ] || d="$d exit 0 with a reachable vulnerability in backend;"
    grep -qi 'backend.*vulnerab' "$OUT" || d="$d no report naming backend's vulnerabilities: $(out);"
    grep -q '^cli|' "$LOG" || d="$d cli was not scanned after backend failed;"
    verdict "$name" "$d"
}
test_vuln_fails_and_scans_rest

test_scan_error_fails() {
    name="scan-error-fails-and-is-reported-as-an-error"
    new_repo "$RELEASE_YML"; reset; write_go ''; write_govulncheck "$BIN"
    echo 1 > "$SANDBOX/rc.cli"
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -ne 0 ] || d="$d exit 0 when govulncheck errored on cli;"
    grep -qi 'cli.*error' "$OUT" || d="$d no report naming cli's scan error: $(out);"
    verdict "$name" "$d"
}
test_scan_error_fails

# absent_case <name> <with-go> — no govulncheck anywhere; <with-go>=yes keeps a
# fake go whose GOBIN is unset and whose GOPATH bin is empty.
absent_case() {
    new_repo "$RELEASE_YML"; reset
    [ "$2" = yes ] && write_go ''
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -ne 0 ] || d="$d exit 0 with no govulncheck (want a failure, never a skip);"
    grep -q 'go install golang.org/x/vuln/cmd/govulncheck' "$OUT" || d="$d no install command in: $(out);"
    verdict "$1" "$d"
}
absent_case "absent-govulncheck-fails-with-the-install-command" yes
absent_case "absent-go-and-govulncheck-fails-with-the-install-command" no

# found_case <name> <gobin> <dir> — govulncheck only in <dir>, off PATH.
found_case() {
    new_repo "$RELEASE_YML"; reset; write_go "$2"; write_govulncheck "$3"
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -eq 0 ] || d="$d exit $rc: $(out);"
    [ -s "$LOG" ] || d="$d the govulncheck in $3 never ran;"
    verdict "$1" "$d"
}
found_case "finds-govulncheck-in-the-first-gopath-entrys-bin" '' "$SANDBOX/gopath/bin"
found_case "finds-govulncheck-in-gobin" "$SANDBOX/gobin" "$SANDBOX/gobin"

test_no_release_version() {
    name="no-go-version-in-release-yml-fails-without-scanning"
    new_repo "jobs:
  build-binary:
    steps:
      - uses: actions/setup-go@0000000000000000000000000000000000000000 # v7"
    reset; write_go ''; write_govulncheck "$BIN"
    rc=$(run_gate "$REPO")
    d=""
    [ "$rc" -ne 0 ] || d="$d exit 0 with no go-version to pin;"
    grep -q 'release.yml' "$OUT" || d="$d failure does not name release.yml: $(out);"
    [ ! -s "$LOG" ] || d="$d scanned anyway, under an unpinned Go;"
    verdict "$name" "$d"
}
test_no_release_version

# ---------------------------------------------------------------------------
# The real script in the real repo (fakes still on PATH): tie it to the real
# release.yml and ci.yml, so neither can drift from the gate unnoticed.
# ---------------------------------------------------------------------------
reset; write_go ''; write_govulncheck "$BIN"
REAL_RC=$(run_gate "$REPO_ROOT")

test_real_release_version() {
    name="real-release-yml-build-binary-go-version-is-the-toolchain"
    want=$(job_block "$REPO_ROOT/.github/workflows/release.yml" build-binary \
        | sed -n "s/^[[:space:]]*go-version:[[:space:]]*['\"]\{0,1\}\([0-9][0-9.]*\)['\"]\{0,1\}[[:space:]]*$/\1/p")
    d=""
    [ -n "$want" ] || d="$d no go-version in release.yml's build-binary job;"
    [ "$REAL_RC" -eq 0 ] || d="$d exit $REAL_RC in the real repo: $(out);"
    [ -s "$LOG" ] || d="$d govulncheck never ran in the real repo;"
    ! grep -v "^[^|]*|go$want|" "$LOG" | grep -q . \
        || d="$d a scan ran without GOTOOLCHAIN=go$want: $(tr '\n' ' ' < "$LOG");"
    verdict "$name" "$d"
}
test_real_release_version

test_modules_match_ci() {
    name="scanned-modules-equal-ci-audit-go-modules"
    ci=$(job_block "$REPO_ROOT/.github/workflows/ci.yml" audit-go \
        | sed -n 's/.*cd \([A-Za-z0-9_./-]*\) && .*govulncheck.*/\1/p' | sort)
    got=$(scanned)
    d=""
    [ -n "$ci" ] || d="$d no govulncheck module found in ci.yml's audit-go job;"
    [ "$got" = "$ci" ] \
        || d="$d preflight scans [$(printf '%s' "$got" | tr '\n' ' ')] but CI audit-go scans [$(printf '%s' "$ci" | tr '\n' ' ')];"
    verdict "$name" "$d"
}
test_modules_match_ci

finish
