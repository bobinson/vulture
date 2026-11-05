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
#   - verdict name detail      -> pass if detail is empty, else fail with it.
#
# Workflow (YAML) helpers for the static .github/ suites:
#   - SHA_PIN_RE               -> ERE for a `@<40-hex> # vN` action pin.
#   - noncomment file          -> file with YAML comments stripped.
#   - unpinned_uses file       -> `uses:` lines whose ref can move (only a
#                                 `./` path is exempt).
#   - job_block file job       -> comment-stripped body of jobs.<job>.
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

# verdict <name> <detail> — pass <name> when <detail> is empty, else fail it
# with <detail> (the accumulate-reasons-then-report shape of the suites).
verdict() {
    if [ -z "$2" ]; then pass "$1"; else fail "$1" "$2"; fi
}

# ---------------------------------------------------------------------------
# Workflow (YAML) helpers. Line-oriented on purpose: CI shells have no YAML
# parser, and the workflows keep the 2-space job indentation these rely on.
# ---------------------------------------------------------------------------

# A third-party action pinned to a 40-hex commit SHA with a `# vN` comment —
# the repo convention (e.g. `actions/checkout@34e1...8d5 # v4`).
SHA_PIN_RE='@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]'

# A step's or job's `uses:` key, up to the first character of its value.
USES_RE='^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*'

# A `uses:` whose (unquoted) value cannot move, matched from the value's first
# character so a pin written only in the trailing comment does not count: an
# in-repo `./` path, a `docker://` image pinned by `@sha256:` digest, or an
# <owner>/<repo>[/<path>] ref pinned per SHA_PIN_RE.
PINNED_USES_RE="$USES_RE"'(\./|docker://[^[:space:]@]+@sha256:[0-9a-f]{64}([[:space:]]|$)|[A-Za-z0-9-]+/[^[:space:]@]+'"$SHA_PIN_RE"')'

# noncomment <file> — print <file> with YAML comments stripped: drop whole-line
# comments (first non-blank char is `#`) and strip inline trailing ` #...`, so a
# negative guard does not trip on a comment that NAMES the forbidden token.
# Whole-line comments go first: stripping first would leave an indented comment
# behind as a whitespace-only line.
noncomment() {
    sed -e '/^[[:space:]]*#/d' -e 's/[[:space:]]#.*$//' "$1"
}

# unpinned_uses <file> — print every `uses:` line in <file> that
# PINNED_USES_RE does not accept: a tag, branch or missing ref, a docker://
# image without a digest, or a remote ref whatever its path (only a value that
# starts `./` is in-repo). Empty if all are pinned.
unpinned_uses() {
    grep -E "$USES_RE" "$1" | grep -Ev "$PINNED_USES_RE" || true
}

# job_block <workflow> <job> — print the comment-stripped body of jobs.<job>:
# the lines after its 2-space-indented key, up to the next job key or the next
# top-level key. Empty when the workflow has no such job.
job_block() {
    noncomment "$1" | awk -v j="$2" '
        /^jobs:/ { f = 1; next }
        f && /^[^[:space:]]/ { f = 0 }
        f && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { c = $1; sub(/:$/, "", c); next }
        f && c == j { print }'
}
