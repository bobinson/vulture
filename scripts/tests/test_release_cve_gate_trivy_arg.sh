#!/usr/bin/env sh
#
# Behaviour tests for scripts/release-cve-gate.sh: how it reads its <trivy>
# argument (feature 0102). As in a shell, a value with a slash is a path, taken
# from the caller's directory when relative, and a bare name is a command. The
# gate looks a bare name up on its own PATH (/usr/bin:/bin) only, never in the
# caller's directory or on the caller's PATH. The gate's other behaviour is
# pinned by test_release_cve_gate.sh and test_release_cve_gate_isolation.sh.
#
# Cases:
#   bare-name-is-a-command  the caller's directory, which is also on the
#                           caller's PATH, holds a trivy stand-in named like the
#                           bare <trivy> value, a name absent from /usr/bin and
#                           /bin: the stand-in never runs, and the gate fails
#                           closed (exit 1, "trivy failed on <tarball>")
#   slash-name-is-a-path    the same stand-in given as ./<name>: it runs, inside
#                           the work dir, and the clean tarball passes (exit 0)
#
# Hermetic: the gate runs from a sandbox checkout (dist/, .trivyignore) over a
# fixture tarball (VERSION and bin/vulture). The stand-in logs each call's
# working directory and reports the Go binary with no finding.
#
# Usage: sh scripts/tests/test_release_cve_gate_trivy_arg.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"
REPO_ROOT=$(repo_root "$0")
# shellcheck source=scripts/lib/hash.sh
. "$REPO_ROOT/scripts/lib/hash.sh"

GATE="$REPO_ROOT/scripts/release-cve-gate.sh"
TB=vulture-v9.9.9-linux-amd64
# The stand-in's name: no host installs a program by it in /usr/bin or /bin.
NAME=vulture-test-trivy-stand-in
CASES='bare-name-is-a-command slash-name-is-a-path'

make_sandbox
SB=$(cd "$SANDBOX" && pwd -P)
C="$SB/checkout"
W="$SB/work"

# write_stand_in <file> — the trivy stand-in: each call appends its working
# directory to $SB/calls and writes a clean report holding the Go binary to
# its --output.
write_stand_in() {
    { printf "#!/bin/sh\nSB='%s'\n" "$SB"; cat <<'SHIM'; } > "$1"
pwd -P >> "$SB/calls"
out=/dev/stdout
while [ $# -gt 0 ]; do
    [ "$1" != --output ] || { out=$2; shift; }
    shift
done
printf '{"Results": [{"Target": "bin/vulture", "Type": "gobinary", "Packages": [{"Name": "stdlib"}]}]}\n' > "$out"
SHIM
    chmod 0755 "$1"
}

# write_checkout — a fresh checkout $C: the fixture as dist/$TB.tar.gz with its
# digest in expected.sha256, a waiver-free .trivyignore and the stand-in as
# $C/$NAME; no work dir, no call log.
write_checkout() {
    rm -rf "$C" "$W" "$SB/calls" "$SB/fx"
    mkdir -p "$C/dist" "$SB/fx/bin"
    printf 'v9.9.9\n' > "$SB/fx/VERSION"
    printf 'go binary\n' > "$SB/fx/bin/vulture"
    (cd "$SB/fx" && tar -czf "$C/dist/$TB.tar.gz" .)
    printf '%s  %s\n' "$(sha256_of "$C/dist/$TB.tar.gz")" "$TB.tar.gz" > "$C/expected.sha256"
    printf '# no waivers\n' > "$C/.trivyignore"
    write_stand_in "$C/$NAME"
}

# gate <caller PATH> <trivy> — the gate from $C with release.yml's other
# arguments, in an environment emptied but for PATH and HOME. Sets RC; stderr
# in $SB/err.
gate() {
    (cd "$C" && /usr/bin/env -i PATH="$1" HOME="$SB/home" "$GATE" "$2" dist "$W" .trivyignore "$C/expected.sha256") \
        > /dev/null 2> "$SB/err"
    RC=$?
}

expect_exit() {
    [ "$RC" -eq "$1" ] || printf ' exit %s, want %s (stderr: %s);' "$RC" "$1" "$(head -c 300 "$SB/err" | tr '\n' '|')"
}

# expect_err <text> <also on that line> — a stderr line holds both.
expect_err() {
    grep -F -- "$1" "$SB/err" | grep -Fq -- "$2" || printf ' stderr lacks "%s" naming %s;' "$1" "$2"
}

# ran_in_work_dir — the stand-in ran, and every call ran inside the work dir.
ran_in_work_dir() {
    [ -s "$SB/calls" ] || { printf ' the stand-in never ran;'; return; }
    grep -vF -- "$W/" "$SB/calls" | sed 's/^/ a call ran in [/; s/$/];/' | tr -d '\n'
}

case_bare_name_is_a_command() {
    write_checkout
    gate "$C:$PATH" "$NAME"
    expect_exit 1
    expect_err 'trivy failed on' "$TB"
    [ ! -e "$SB/calls" ] || printf " the caller's %s ran;" "$NAME"
}

case_slash_name_is_a_path() {
    write_checkout
    gate "$PATH" "./$NAME"
    expect_exit 0
    ran_in_work_dir
}

for _c in $CASES; do
    verdict "$_c" "$("case_$(printf '%s' "$_c" | sed 's/-/_/g')")"
done
finish
