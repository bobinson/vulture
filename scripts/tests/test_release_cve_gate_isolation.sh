#!/usr/bin/env sh
#
# Behaviour tests for scripts/release-cve-gate.sh: what the caller's directory
# and an existing work dir can do to the gate (feature 0102). The gate's other
# behaviour is pinned by test_release_cve_gate.sh.
#
# Trivy reads files from its working directory whatever its flags: trivy 0.71.0
# loads ./trivy-secret.yaml for the secret scanner when no --secret-config is
# given, and that file can disable every secret rule. In CI the caller's
# directory is the repo checkout, so the gate must not run Trivy there.
#
# Cases:
#   caller-secret-config   the caller's directory holds a trivy-secret.yaml that
#                          disables the secret rules: a tarball holding a secret
#                          still fails the gate (exit 1, the findings line), and
#                          every trivy call runs inside the work dir
#   relative-arguments     <trivy>, <dist-dir>, <work-dir> and <ignorefile> given
#                          relative to the caller's directory: a clean tarball
#                          passes, every trivy call runs inside the work dir,
#                          and the work dir is gone at exit
#   unreadable-work-dir    an existing work dir the caller cannot list (mode 000,
#                          or 0300: write and search only) that holds a file:
#                          exit 1, "work dir not empty", no trivy call, and the
#                          dir and its file are still there
#
# Hermetic: the gate runs from a sandbox checkout (dist/, .trivyignore) over a
# fixture tarball (VERSION and bin/vulture, plus creds.txt standing in for a
# secret where a case needs one), with a trivy shim in place of trivy. The shim
# logs its working directory and answers like trivy 0.71.0 for what these cases
# need: a JSON report with the Go binary, plus a CRITICAL secret for creds.txt
# (exit --exit-code) unless the secret config it reads, ./trivy-secret.yaml by
# default, disables that rule.
#
# Usage: sh scripts/tests/test_release_cve_gate_isolation.sh
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
CASES='caller-secret-config relative-arguments unreadable-work-dir'

make_sandbox
trap 'chmod -R u+rwx "$SANDBOX" 2>/dev/null; rm -rf "$SANDBOX"' EXIT INT TERM
SB=$(cd "$SANDBOX" && pwd -P)
C="$SB/checkout"
W="$SB/work"
SHIM="$SB/bin/trivy"

# write_shim — the trivy stand-in (see the header). Each call writes
# "cwd <dir>" and "sub <sub>" to $SB/log/<n>.call.
write_shim() {
    mkdir -p "$SB/bin"
    { printf "#!/bin/sh\nSB='%s'\n" "$SB"; cat <<'SHIM'; } > "$SHIM"
n=$(( $(cat "$SB/ncalls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$SB/ncalls"
printf 'cwd %s\n' "$(pwd -P)" > "$SB/log/$n.call"
sub="" tgt="" out=/dev/stdout code=0 rules=trivy-secret.yaml
while [ $# -gt 0 ]; do
    case $1 in
        --skip-version-check) ;;
        --output) out=$2; shift ;;
        --exit-code) code=$2; shift ;;
        --secret-config) rules=$2; shift ;;
        -*) shift ;;
        *) if [ -z "$sub" ]; then sub=$1; else tgt=$1; fi ;;
    esac
    shift
done
printf 'sub %s\n' "$sub" >> "$SB/log/$n.call"
case $sub in
    rootfs) ;;
    convert) printf 'TABLE %s\n' "$tgt"; exit 0 ;;
    *) echo "FATAL unknown command $sub" >&2; exit 1 ;;
esac
secret=""
[ ! -f "$tgt/creds.txt" ] || grep -qs 'aws-access-key-id' "$rules" || secret=1
{
    printf '{\n  "SchemaVersion": 2,\n  "ArtifactName": "%s",\n  "ArtifactType": "filesystem",\n  "Results": [\n' "$tgt"
    printf '    {"Target": "bin/vulture", "Class": "lang-pkgs", "Type": "gobinary", "Packages": [{"Name": "stdlib", "Version": "1.0.0"}]}'
    [ -z "$secret" ] || printf ',\n    {"Target": "creds.txt", "Class": "secret", "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL"}]}'
    printf '\n  ]\n}\n'
} > "$out"
[ -z "$secret" ] || exit "$code"
exit 0
SHIM
    chmod 0755 "$SHIM"
}

# build_fixture <kind> — $SB/fx/<kind>.tar.gz laid out like a release tarball
# (VERSION, bin/vulture); "secret" adds creds.txt.
build_fixture() {
    _bf="$SB/fx/$1"
    mkdir -p "$_bf/bin"
    printf 'v9.9.9\n' > "$_bf/VERSION"
    printf 'go binary\n' > "$_bf/bin/vulture"
    [ "$1" != secret ] || printf 'a stand-in for a secret\n' > "$_bf/creds.txt"
    (cd "$_bf" && tar -czf "$_bf.tar.gz" .)
}

# scenario <kind> — a fresh checkout $C: that fixture as dist/$TB.tar.gz with
# its digest in expected.sha256, a waiver-free .trivyignore; no work dir, an
# empty trivy log.
scenario() {
    chmod -R u+rwx "$C" "$W" 2>/dev/null
    rm -rf "$C" "$W" "$SB/log" "$SB/ncalls"
    mkdir -p "$C/dist" "$SB/log"
    cp "$SB/fx/$1.tar.gz" "$C/dist/$TB.tar.gz"
    printf '%s  %s\n' "$(sha256_of "$C/dist/$TB.tar.gz")" "$TB.tar.gz" > "$C/expected.sha256"
    printf '# no waivers\n' > "$C/.trivyignore"
}

# run <cmd...> — run from $C with an emptied environment (PATH, HOME). Sets RC;
# stdout and stderr in $SB/out, $SB/err.
run() {
    (cd "$C" && /usr/bin/env -i PATH="$PATH" HOME="$SB/home" "$@") > "$SB/out" 2> "$SB/err"
    RC=$?
}

# gate — the gate with release.yml's arguments.
gate() { run "$GATE" "$SHIM" dist "$W" .trivyignore "$C/expected.sha256"; }

calls() { cat "$SB/ncalls" 2>/dev/null || echo 0; }

expect_exit() {
    [ "$RC" -eq "$1" ] || printf ' exit %s, want %s (stderr: %s);' "$RC" "$1" "$(head -c 300 "$SB/err" | tr '\n' '|')"
}

# expect_err <text> [<also on that line>] — a stderr line holds both.
expect_err() {
    grep -F -- "$1" "$SB/err" | grep -Fq -- "${2:-$1}" || printf ' stderr lacks "%s"%s;' "$1" "${2:+ naming $2}"
}

# cwd_detail <log> — what is wrong with one trivy call's working directory.
cwd_detail() {
    _cw=$(sed -n 's/^cwd //p' "$1")
    case $_cw in "$W"/*) ;; *) printf ' %s ran in [%s];' "${1##*/}" "$_cw" ;; esac
}

# in_work_dir — every trivy call (at least one) ran inside the work dir.
in_work_dir() {
    [ "$(calls)" -gt 0 ] || { printf ' trivy never ran;'; return; }
    for _f in "$SB"/log/*.call; do cwd_detail "$_f"; done
}

case_caller_secret_config() {
    scenario secret
    printf 'disable-rules:\n  - aws-access-key-id\n' > "$C/trivy-secret.yaml"
    gate
    expect_exit 1
    expect_err 'HIGH/CRITICAL findings' "$TB"
    in_work_dir
}

# The checkout's own copy of the shim, and a work dir inside the checkout.
case_relative_arguments() {
    scenario clean
    mkdir -p "$C/tools" && cp "$SHIM" "$C/tools/trivy"
    W="$C/work"
    run "$GATE" tools/trivy dist work .trivyignore expected.sha256
    expect_exit 0
    in_work_dir
    [ ! -e "$W" ] || printf ' the work dir is still there at exit;'
}

# kept_detail — what is wrong after a refused gate: a trivy call, or the work
# dir or its file gone.
kept_detail() {
    [ "$(calls)" -eq 0 ] || printf ' %s trivy call(s), want 0;' "$(calls)"
    [ -f "$W/keep.txt" ] || printf ' the work dir or its file was removed;'
}

# unreadable_one <mode> — the gate over an existing work dir of <mode> that
# holds a file.
unreadable_one() {
    scenario clean
    mkdir -p "$W"
    printf 'keep\n' > "$W/keep.txt"
    chmod "$1" "$W"
    gate
    chmod 0700 "$W" 2>/dev/null
    _r="$(expect_exit 1)$(expect_err 'release-cve-gate: work dir not empty:')$(kept_detail)"
    [ -z "$_r" ] || printf ' [%s]%s' "$1" "$_r"
}

case_unreadable_work_dir() {
    for _m in 000 0300; do unreadable_one "$_m"; done
}

write_shim
build_fixture secret
build_fixture clean
for _c in $CASES; do
    if [ -f "$GATE" ]; then
        verdict "$_c" "$("case_$(printf '%s' "$_c" | sed 's/-/_/g')")"
    else
        fail "$_c" "scripts/release-cve-gate.sh is missing"
    fi
done
finish
