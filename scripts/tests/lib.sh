# shellcheck shell=sh
#
# scripts/tests/lib.sh — shared POSIX-sh harness for the scripts/tests/*.sh
# suites. SOURCE this, do NOT run it: it defines counters + helpers and has no
# side effects of its own.
#
# Contract (matches scripts/tests/test_install_sh.sh):
#   - POSIX sh, no bashisms.
#   - pass()/fail() bump PASS/FAIL and print one line each.
#   - finish() prints the "N passed, M failed" tally and exits 1 on any FAIL.
#   - repo_root "$0"            -> absolute repo root, two levels above $0's dir.
#   - require_file_or_bail name path  -> fail + finish() (exit) if path absent.
#   - assert_file_matches name file ere why -> pass if `grep -Eq ere file`.
#   - make_sandbox             -> mktemp -d into $SANDBOX + EXIT/INT/TERM trap.
#
# Usage:
#   set -u
#   . "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"  # shellcheck source=scripts/tests/lib.sh
#   ...
#   finish

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf 'PASS [%s]\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$1" "$2"; }

# finish — print the tally and exit non-zero if any case FAILed.
finish() {
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ] || exit 1
}

# repo_root <script-path> — absolute repo root (two dirs above the script's dir).
repo_root() {
    CDPATH='' cd -- "$(dirname -- "$1")/../.." && pwd
}

# require_file_or_bail <name> <path> — pass-through if <path> is a regular file;
# otherwise record a failure and finish() (which exits non-zero).
require_file_or_bail() {
    [ -f "$2" ] && return 0
    fail "$1" "not found at $2"
    finish
}

# assert_file_matches <name> <file> <ere> <why> — pass if <file> matches the
# extended regex <ere>, else fail with <why>.
assert_file_matches() {
    if grep -Eq "$3" "$2"; then
        pass "$1"
    else
        fail "$1" "$4"
    fi
}

# make_sandbox — create a private temp dir in $SANDBOX and arrange for its
# removal on EXIT/INT/TERM.
make_sandbox() {
    SANDBOX=$(mktemp -d 2>/dev/null || mktemp -d -t vulture-test)
    trap 'rm -rf "$SANDBOX"' EXIT INT TERM
}
