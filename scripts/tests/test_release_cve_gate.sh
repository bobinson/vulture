#!/usr/bin/env sh
#
# Behaviour tests for scripts/release-cve-gate.sh <trivy> <dist-dir> <work-dir>
# <ignorefile> <expected-sums> (feature 0102, the release CVE gate).
#
# The gate refuses (exit 1, no scan) unless every argument is given, the work
# dir is absent or empty, the waiver file passes trivyignore_check for today,
# the dist dir holds vulture-*.tar.gz tarballs and no stale *.vulns.json, and
# every tarball's SHA-256 is in the expected sums. It then extracts one tarball
# at a time into the work dir, runs `trivy rootfs` over the tree (the report is
# dist/<tarball>.vulns.json) and `trivy sbom` over each wheel SBOM
# (*.dist-info/sboms/*.json) in it, and removes the tree. tar and trivy get an
# emptied environment. Exit 3 from trivy is a finding (the table is printed
# with `trivy convert`); any other failure, or a report without the Go binary
# or, where the tree bundles Python, the Python packages, fails the gate too.
#
# Hermetic: the gate runs from a sandbox checkout (dist/, .trivyignore) with
# release.yml's relative arguments, over fixture tarballs laid out like
# build-release.sh's, with a trivy shim in place of trivy. The shim logs its
# argv (path values resolved, comma lists sorted), the environment it received
# and what it found on disk, and answers like trivy 0.71.0: a JSON report whose
# results follow the tree (the fixture's VERSION names a mode), --exit-code on
# findings, exit 1 on an unknown scanner or a missing --config file, and the
# cwd's trivy.yaml read when no --config is given.
#
# Cases:
#   usage                       fewer than 5 arguments: exit 1, the usage line
#   refuse-no-tarballs          no vulture-*.tar.gz in the dist dir
#   refuse-missing-ignorefile   the waiver file does not exist
#   refuse-invalid-ignorefile   the waiver file fails trivyignore_check
#   refuse-work-dir-not-empty   the work dir holds a file
#   refuse-stale-report         a *.vulns.json is already in the dist dir
#   refuse-digest-mismatch      a tarball's digest differs from, or is missing
#                               in, the expected sums
#     (each refusal: exit 1, 0 trivy calls, nothing extracted)
#   clean-reports       two clean tarballs: exit 0; dist/<tarball>.vulns.json is
#                       each tree's rootfs report and the only report file;
#                       the tarballs are unchanged
#   rootfs-argv         one `trivy rootfs` per tarball with exactly
#                       --scanners vuln,secret --severity HIGH,CRITICAL
#                       --ignorefile <f> --config <work>/empty.yaml --cache-dir
#                       <work>/cache --skip-version-check --format json --output
#                       dist/<tarball>.vulns.json --exit-code 3, over a tree in
#                       the work dir holding bin/vulture, one tree on disk at a
#                       time; never `trivy fs`
#   env-isolation       with TRIVY_*, TAR_OPTIONS and GITHUB_* set and a
#                       trivy.yaml in the cwd: every trivy call sees only PATH
#                       (/usr/bin:/bin) and HOME (inside the work dir), tar
#                       ignores TAR_OPTIONS, and trivy reads the empty
#                       <work>/empty.yaml, never the cwd's trivy.yaml
#   sbom-pass           each wheel SBOM goes to `trivy sbom` once, with the
#                       severity, waiver, config, cache and --exit-code 3 flags
#                       and no skip, VEX or ignore-unfixed flag
#   red-first-continues the first tarball has findings (exit 3): exit 1, the
#                       second is still scanned, and `trivy convert --format
#                       table` runs for the first report only
#   tool-error          trivy exits 1: exit 1, "trivy failed on <tb>"
#   no-coverage         a report with no results, without the Go binary, or
#                       without the Python packages of a bundled runtime:
#                       exit 1, "no coverage for <tb>"
#   sbom-red            a finding in a wheel SBOM fails the gate
#   corrupt-tarball     exit 1, "cannot extract <tb>", nothing scanned
#   mode-000-removed    a tree holding a mode-000 directory is still removed:
#                       the work dir is empty (or gone) at exit
#
# Usage: sh scripts/tests/test_release_cve_gate.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL). The mode-000 fixture needs GNU tar (`--mode`), as the gate does.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"
REPO_ROOT=$(repo_root "$0")
# shellcheck source=scripts/lib/hash.sh
. "$REPO_ROOT/scripts/lib/hash.sh"

GATE="$REPO_ROOT/scripts/release-cve-gate.sh"
LINUX=vulture-v9.9.9-linux-amd64
DARWIN=vulture-v9.9.9-darwin-arm64 # sorts first
CASES='usage refuse-no-tarballs refuse-missing-ignorefile refuse-invalid-ignorefile
refuse-work-dir-not-empty refuse-stale-report refuse-digest-mismatch clean-reports
rootfs-argv env-isolation sbom-pass red-first-continues tool-error no-coverage
sbom-red corrupt-tarball mode-000-removed'

make_sandbox
trap 'chmod -R u+rwx "$SANDBOX" 2>/dev/null; rm -rf "$SANDBOX"' EXIT INT TERM
SB=$(cd "$SANDBOX" && pwd -P)
C="$SB/checkout"
W="$SB/work"
E="$SB/expected.sha256"
SHIM="$SB/bin/trivy"

# write_shim — the trivy stand-in (see the header). Each call appends
# "sub|flag|pos|env|home|path|config|fixture|tree_bin|trees ..." lines to
# $SB/log/<n>.call.
write_shim() {
    mkdir -p "$SB/bin"
    printf '%s\n' "$W" > "$SB/workdir"
    { printf "#!/bin/sh\nSB='%s'\n" "$SB"; cat <<'SHIM'; } > "$SHIM"
n=$(( $(cat "$SB/ncalls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$SB/ncalls"
F="$SB/log/$n.call"
W=$(cat "$SB/workdir")
rec() { printf '%s\n' "$*" >> "$F"; }
abspath() {
    if [ -d "$1" ]; then (cd "$1" && pwd -P); return; fi
    _d=$(cd "$(dirname "$1")" 2>/dev/null && pwd -P) || { printf '%s\n' "$1"; return; }
    printf '%s/%s\n' "$_d" "$(basename "$1")"
}
sorted_csv() { printf '%s\n' "$1" | tr ',' '\n' | LC_ALL=C sort | paste -s -d, -; }
if [ -r "/proc/$$/environ" ]; then tr '\0' '\n' < "/proc/$$/environ"; else env | grep -Ev '^(PWD|OLDPWD|SHLVL|_)='; fi \
    | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/env \1/p' >> "$F"
rec "home ${HOME:-}"
rec "path ${PATH:-}"
sub="" tgt="" config="" code=0 out="" fmt="" scanners=""
while [ $# -gt 0 ]; do
    a=$1; shift
    case $a in
        --*=*) k=${a%%=*}; v=${a#*=} ;;
        --skip-version-check|--quiet|-q|--debug|-d|--no-progress|--list-all-pkgs|--skip-db-update|--skip-java-db-update|--offline-scan|--ignore-unfixed|--version|-v)
            rec "flag $a"; continue ;;
        -*) k=$a; v=${1:-}; [ $# -eq 0 ] || shift ;;
        *) if [ -z "$sub" ]; then sub=$a; rec "sub $a"; else tgt=$(abspath "$a"); rec "pos $tgt"; fi; continue ;;
    esac
    case $k in
        --ignorefile|--config|--cache-dir|--output) v=$(abspath "$v") ;;
        --scanners|--severity) v=$(sorted_csv "$v") ;;
    esac
    rec "flag $k $v"
    case $k in
        --config) config=$v ;; --exit-code) code=$v ;; --output) out=$v ;;
        --format) fmt=$v ;; --scanners) scanners=$v ;;
    esac
done
if [ -n "$config" ]; then
    [ -f "$config" ] || { echo "FATAL config file \"$config\" loading error" >&2; exit 1; }
    rec "config $config $(wc -c < "$config" | tr -d ' ')"
elif [ -f trivy.yaml ]; then
    rec "config $(abspath trivy.yaml) $(wc -c < trivy.yaml | tr -d ' ')"
else
    rec "config none"
fi
case $sub in sbom) allowed=,license,vuln, ;; *) allowed=,license,misconfig,secret,vuln, ;; esac
for s in $(printf '%s' "$scanners" | tr ',' ' '); do
    case $allowed in *",$s,"*) ;; *) echo "FATAL invalid argument for --scanners: $s" >&2; exit 1 ;; esac
done
case $sub in
    rootfs|fs|filesystem) tree=$tgt type=filesystem ;;
    sbom) tree=${tgt%%/runtime/python/*} type=cyclonedx ;;
    convert) [ -f "$tgt" ] || exit 1; printf 'TABLE %s\n' "$tgt"; exit 0 ;;
    '') printf 'Version: 0.71.0\n'; exit 0 ;;
    *) echo "FATAL unknown command $sub" >&2; exit 1 ;;
esac
mode=$(sed -n 1p "$tree/VERSION" 2>/dev/null)
rec "fixture $(sed -n 2p "$tree/VERSION" 2>/dev/null)"
if [ -f "$tree/bin/vulture" ]; then rec "tree_bin yes"; else rec "tree_bin no"; fi
rec "trees $(find "$W" -type f -name VERSION 2>/dev/null | wc -l | tr -d ' ')"
[ "$mode" != toolerr ] || { echo "FATAL scan error" >&2; exit 1; }
result() {
    printf '    {\n      "Target": "%s",\n      "Class": "lang-pkgs",\n      "Type": "%s",\n      "Packages": [\n        {\n          "Name": "%s",\n          "Version": "1.0.0"\n        }\n      ]' "$1" "$2" "$3"
    [ -z "$4" ] || printf ',\n      "Vulnerabilities": [\n        {\n          "VulnerabilityID": "CVE-2099-0001",\n          "PkgName": "%s",\n          "Severity": "HIGH"\n        }\n      ]' "$3"
    printf '\n    }'
}
red="" go="" py=""
if [ "$sub" = sbom ]; then
    [ "$mode" != sbomred ] || red=red
    res=$(result "${tgt##*/}" cargo serde "$red")
else
    [ "$mode" != red ] || red=red
    [ "$mode" = nogo ] || [ ! -f "$tree/bin/vulture" ] || go=$(result bin/vulture gobinary stdlib "$red")
    [ "$mode" = nopy ] || [ ! -d "$tree/runtime/python" ] || py=$(result Python python-pkg demo "")
    if [ -n "$py" ] && [ -n "$go" ]; then res="$py,
$go"; else res="$py$go"; fi
fi
{
    if [ "$fmt" != json ]; then printf 'TABLE %s\n' "$tgt"
    else
        printf '{\n  "SchemaVersion": 2,\n  "Trivy": {\n    "Version": "0.71.0"\n  },\n  "ArtifactName": "%s",\n  "ArtifactType": "%s"' "$tgt" "$type"
        [ "$mode" = empty ] || printf ',\n  "Results": [\n%s\n  ]' "$res"
        printf '\n}\n'
    fi
} > "${out:-/dev/stdout}"
[ -z "$red" ] || exit "$code"
exit 0
SHIM
    chmod 0755 "$SHIM"
}

# fixture <name> <mode> [locked] — a tarball laid out like build-release.sh's
# (VERSION, bin/vulture, a bundled runtime/python with two wheel SBOMs) whose
# VERSION holds <mode> and <name>; "locked" adds a mode-000 directory. Built
# once, printed as a path.
fixture() {
    _fx="$SB/fx/$1.$2${3:+.$3}"
    [ -f "$_fx.tar.gz" ] || build_fixture "$_fx" "$@"
    printf '%s\n' "$_fx.tar.gz"
}

build_fixture() {
    _sp="$1/runtime/python/lib/python3.12/site-packages"
    mkdir -p "$1/bin" "$_sp/demo-1.0.dist-info/sboms" "$_sp/other-2.0.dist-info/sboms"
    printf '%s\n%s\n' "$3" "$2" > "$1/VERSION"
    printf 'go binary\n' > "$1/bin/vulture"
    printf 'Name: demo\n' > "$_sp/demo-1.0.dist-info/METADATA"
    for _w in demo-1.0/demo other-2.0/other; do
        printf '{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}\n' \
            > "$_sp/${_w%/*}.dist-info/sboms/${_w#*/}.cyclonedx.json"
    done
    [ -z "${4:-}" ] || { mkdir -p "$1/runtime/locked" && printf 'x\n' > "$1/runtime/locked/f"; }
    (cd "$1" && tar -cf "$1.tar" . && { [ -z "${4:-}" ] || tar -rf "$1.tar" --no-recursion --mode=0 ./runtime/locked; }) \
        && gzip -n "$1.tar"
}

# scenario — a fresh checkout $C (dist/, a waiver-free .trivyignore), no work
# dir, empty expected sums and an empty trivy log.
scenario() {
    chmod -R u+rwx "$C" "$W" 2>/dev/null
    rm -rf "$C" "$W" "$SB/log" "$SB/ncalls"
    mkdir -p "$C/dist" "$SB/log"
    printf '# no waivers\n' > "$C/.trivyignore"
    : > "$E"
}

# add <name> <mode> [locked] — that fixture into dist/, its digest into $E.
add() {
    cp "$(fixture "$@")" "$C/dist/$1.tar.gz"
    printf '%s  %s\n' "$(sha256_of "$C/dist/$1.tar.gz")" "$1.tar.gz" >> "$E"
}

# run <cmd...> — run from $C with an emptied environment (PATH, HOME) plus any
# leading NAME=value words. Sets RC; stdout and stderr in $SB/out, $SB/err.
run() {
    (cd "$C" && /usr/bin/env -i PATH="$PATH" HOME="$SB/home" "$@") > "$SB/out" 2> "$SB/err"
    RC=$?
}

# gate [NAME=value...] — the gate with release.yml's arguments.
gate() { run "$@" "$GATE" "$SHIM" dist "$W" .trivyignore "$E"; }

calls() { cat "$SB/ncalls" 2>/dev/null || echo 0; }

# with_sub <sub> — the logs of the `trivy <sub>` calls.
with_sub() { grep -lx "sub $1" "$SB"/log/*.call 2>/dev/null; }

# logged <sub> <key> — the <key> values of every `trivy <sub>` call.
logged() { for _f in $(with_sub "$1"); do sed -n "s/^$2 //p" "$_f"; done; }

# scanned_fixtures — the fixtures `trivy rootfs` saw, sorted, space-joined.
scanned_fixtures() { logged rootfs fixture | LC_ALL=C sort | tr '\n' ' '; }

expect_exit() {
    [ "$RC" -eq "$1" ] || printf ' exit %s, want %s (stderr: %s);' "$RC" "$1" "$(head -c 300 "$SB/err" | tr '\n' '|')"
}

# expect_err <text> [<also on that line>] — a stderr line holds both.
expect_err() {
    grep -F -- "$1" "$SB/err" | grep -Fq -- "${2:-$1}" || printf ' stderr lacks "%s"%s;' "$1" "${2:+ naming $2}"
}

# refused [<text> [<also on that line>]] — exit 1, the message, and neither a
# trivy call nor an extracted tree.
refused() {
    expect_exit 1
    [ $# -eq 0 ] || expect_err "$@"
    [ "$(calls)" -eq 0 ] || printf ' %s trivy call(s), want 0;' "$(calls)"
    [ -z "$(find "$W" -name VERSION 2>/dev/null)" ] || printf ' a tarball was extracted;'
}

# gating_flags — the flags (as the shim logs them) every rootfs and sbom call
# carries: severity, waivers, the empty config, the fresh cache, exit code 3.
gating_flags() {
    printf '%s\n' "--cache-dir $W/cache" "--config $W/empty.yaml" "--exit-code 3" \
        "--ignorefile $C/.trivyignore" "--severity CRITICAL,HIGH" --skip-version-check
}

# want_rootfs_flags <name> — the exact `trivy rootfs` flag lines for <name>.
want_rootfs_flags() {
    { gating_flags; printf '%s\n' "--format json" "--output $C/dist/$1.vulns.json" "--scanners secret,vuln"; } \
        | sed 's/^/flag /' | LC_ALL=C sort
}

# rootfs_detail <log> — what is wrong with one `trivy rootfs` call.
rootfs_detail() {
    _n=$(sed -n 's/^fixture //p' "$1")
    _got=$(grep '^flag ' "$1" | LC_ALL=C sort)
    [ "$_got" = "$(want_rootfs_flags "$_n")" ] || printf ' %s flags [%s];' "$_n" "$(printf '%s' "$_got" | tr '\n' '|')"
    [ "$(grep -c '^pos ' "$1")" -eq 1 ] || printf ' %s: want one target;' "$_n"
    case $(sed -n 's/^pos //p' "$1") in "$W"/*) ;; *) printf ' %s: the tree is not in the work dir;' "$_n" ;; esac
    grep -qx 'tree_bin yes' "$1" || printf ' %s: no bin/vulture in the tree;' "$_n"
    grep -qx 'trees 1' "$1" || printf ' %s: %s on disk;' "$_n" "$(grep '^trees ' "$1")"
}

# sbom_detail <log> — what is wrong with one `trivy sbom` call.
sbom_detail() {
    gating_flags | while IFS= read -r _w; do
        grep -qxF -- "flag $_w" "$1" || printf ' sbom %s lacks %s;' "$(basename "$1")" "$_w"
    done
    _x=$(grep -E '^flag --(skip-db-update|skip-dirs|skip-files|ignore-policy|vex|ignore-unfixed)( |$)' "$1" | tr '\n' ' ')
    [ -z "$_x" ] || printf ' sbom %s passes %s;' "$(basename "$1")" "$_x"
    case $(sed -n 's/^pos //p' "$1") in "$W"/*) ;; *) printf ' sbom %s: target outside the work dir;' "$(basename "$1")" ;; esac
}

# env_detail <log> — what is wrong with one call's environment.
env_detail() {
    _e=$(sed -n 's/^env //p' "$1" | LC_ALL=C sort | tr '\n' ' ')
    [ "$_e" = "HOME PATH " ] || printf ' %s saw [%s], want [HOME PATH];' "$(basename "$1")" "$_e"
    grep -qx 'path /usr/bin:/bin' "$1" || printf ' %s: %s;' "$(basename "$1")" "$(grep '^path ' "$1")"
    case $(sed -n 's/^home //p' "$1") in "$W"/*) ;; *) printf ' %s: HOME outside the work dir;' "$(basename "$1")" ;; esac
}

case_usage() {
    scenario
    add "$LINUX" clean
    run "$GATE" "$SHIM" dist "$W" .trivyignore
    refused 'release-cve-gate: usage: release-cve-gate.sh <trivy> <dist-dir> <work-dir> <ignorefile> <expected-sums>'
    run "$GATE"
    refused 'release-cve-gate: usage:'
}

case_refuse_no_tarballs() {
    scenario
    printf 'not a tarball\n' > "$C/dist/SHA256SUMS"
    gate
    refused 'release-cve-gate: no vulture-*.tar.gz in'
}

case_refuse_missing_ignorefile() {
    scenario
    add "$LINUX" clean
    rm -f "$C/.trivyignore"
    gate
    refused
}

case_refuse_invalid_ignorefile() {
    scenario
    add "$LINUX" clean
    printf 'CVE-2099-0001\n' > "$C/.trivyignore"
    gate
    refused 'release-cve-gate: invalid ignore file'
}

case_refuse_work_dir_not_empty() {
    scenario
    add "$LINUX" clean
    mkdir -p "$W"
    printf 'leftover\n' > "$W/leftover"
    gate
    refused 'release-cve-gate: work dir not empty:'
}

case_refuse_stale_report() {
    scenario
    add "$LINUX" clean
    printf '{}\n' > "$C/dist/$LINUX.vulns.json"
    gate
    refused 'release-cve-gate: stale report' "$LINUX.vulns.json"
}

# Every digest is checked before the first scan: a mismatch on the second
# tarball, and a tarball the sums do not list, each stop the gate cold.
case_refuse_digest_mismatch() {
    scenario
    add "$DARWIN" clean
    add "$LINUX" clean
    grep -vF "$LINUX" "$E" > "$E.part"
    { cat "$E.part"; printf '%064d  %s\n' 0 "$LINUX.tar.gz"; } > "$E"
    gate
    refused 'release-cve-gate: digest mismatch for' "$LINUX"
    cp "$E.part" "$E"
    gate
    refused "$LINUX"
}

case_clean_reports() {
    scenario
    add "$DARWIN" clean
    add "$LINUX" clean
    gate
    expect_exit 0
    for _n in "$DARWIN" "$LINUX"; do
        grep -q '"ArtifactType": "filesystem"' "$C/dist/$_n.vulns.json" 2>/dev/null \
            || printf ' dist/%s.vulns.json is not its rootfs report;' "$_n"
        sha256_verify_in_sums "$C/dist/$_n.tar.gz" "$E" 2>/dev/null || printf ' %s.tar.gz changed;' "$_n"
    done
    _r=$(cd "$C/dist" && find . -name '*.vulns.json' -o -name '*.sbom.json' | LC_ALL=C sort | tr '\n' ' ')
    [ "$_r" = "./$DARWIN.vulns.json ./$LINUX.vulns.json " ] || printf ' report files in dist: [%s];' "$_r"
}

case_rootfs_argv() {
    scenario
    add "$DARWIN" clean
    add "$LINUX" clean
    gate
    expect_exit 0
    _s=$(scanned_fixtures)
    [ "$_s" = "$DARWIN $LINUX " ] || printf ' rootfs scanned [%s], want each tarball once;' "$_s"
    for _f in $(with_sub rootfs); do rootfs_detail "$_f"; done
    [ -z "$(with_sub fs)$(with_sub filesystem)" ] || printf ' ran trivy fs;'
}

case_env_isolation() {
    scenario
    add "$LINUX" clean
    printf 'severity: LOW\nexit-code: 0\nscan:\n  skip-dirs: ["/"]\n' > "$C/trivy.yaml"
    gate TRIVY_SEVERITY=LOW TRIVY_EXIT_CODE=0 TRIVY_SKIP_DIRS=/ TRIVY_CONFIG="$C/trivy.yaml" \
        TRIVY_CACHE_DIR="$SB/home/cache" TAR_OPTIONS=--exclude=bin GITHUB_TOKEN=not-a-token GITHUB_ACTIONS=true
    expect_exit 0
    [ "$(calls)" -gt 0 ] || printf ' trivy never ran;'
    for _f in "$SB"/log/*.call; do [ ! -f "$_f" ] || env_detail "$_f"; done
    for _f in $(with_sub rootfs) $(with_sub sbom); do
        grep -qx "config $W/empty.yaml 0" "$_f" || printf ' %s read [%s];' "$(basename "$_f")" "$(grep '^config' "$_f")"
    done
    for _f in $(with_sub rootfs); do grep -qx 'tree_bin yes' "$_f" || printf ' tar honoured TAR_OPTIONS;'; done
}

case_sbom_pass() {
    scenario
    add "$LINUX" clean
    gate
    expect_exit 0
    _t=$(logged sbom pos | sed 's#.*/site-packages/##' | LC_ALL=C sort | tr '\n' ' ')
    [ "$_t" = "demo-1.0.dist-info/sboms/demo.cyclonedx.json other-2.0.dist-info/sboms/other.cyclonedx.json " ] \
        || printf ' trivy sbom scanned [%s], want each wheel SBOM once;' "$_t"
    for _f in $(with_sub sbom); do sbom_detail "$_f"; done
}

case_red_first_continues() {
    scenario
    add "$DARWIN" red
    add "$LINUX" clean
    gate
    expect_exit 1
    expect_err 'HIGH/CRITICAL findings' "$DARWIN"
    ! grep -F 'HIGH/CRITICAL findings' "$SB/err" | grep -qF "$LINUX" || printf ' the clean tarball was reported;'
    _s=$(scanned_fixtures)
    [ "$_s" = "$DARWIN $LINUX " ] || printf ' rootfs scanned [%s], want both;' "$_s"
    _cv=$(for _f in $(with_sub convert); do grep -qx 'flag --format table' "$_f" && sed -n 's/^pos //p' "$_f"; done | tr '\n' ' ')
    [ "$_cv" = "$C/dist/$DARWIN.vulns.json " ] || printf ' convert --format table ran for [%s], want the first report only;' "$_cv"
}

case_tool_error() {
    scenario
    add "$LINUX" toolerr
    gate
    expect_exit 1
    expect_err 'release-cve-gate: trivy failed on' "$LINUX"
}

case_no_coverage() {
    for _m in empty nogo nopy; do
        scenario
        add "$LINUX" "$_m"
        gate
        _r="$(expect_exit 1)$(expect_err 'release-cve-gate: no coverage for' "$LINUX")"
        [ -z "$_r" ] || printf ' [%s]%s' "$_m" "$_r"
    done
}

case_sbom_red() {
    scenario
    add "$LINUX" sbomred
    gate
    expect_exit 1
    [ -n "$(with_sub sbom)" ] || printf ' no trivy sbom call;'
}

case_corrupt_tarball() {
    scenario
    printf 'not a tarball\n' > "$C/dist/$LINUX.tar.gz"
    printf '%s  %s\n' "$(sha256_of "$C/dist/$LINUX.tar.gz")" "$LINUX.tar.gz" > "$E"
    gate
    expect_exit 1
    expect_err 'release-cve-gate: cannot extract' "$LINUX"
    [ -z "$(with_sub rootfs)$(with_sub sbom)" ] || printf ' scanned a tarball that did not extract;'
}

# An existing, empty work dir is accepted like an absent one.
case_mode_000_removed() {
    scenario
    add "$LINUX" clean locked
    mkdir -p "$W"
    gate
    expect_exit 0
    [ -n "$(with_sub rootfs)" ] || printf ' no rootfs scan;'
    _left=$(find "$W" -mindepth 1 -maxdepth 1 2>/dev/null | sed 's#.*/##' | tr '\n' ' ')
    [ -z "$_left" ] || printf ' the work dir is not empty at exit: [%s];' "$_left"
}

write_shim
for _c in $CASES; do
    if [ -f "$GATE" ]; then
        verdict "$_c" "$("case_$(printf '%s' "$_c" | sed 's/-/_/g')")"
    else
        fail "$_c" "scripts/release-cve-gate.sh is missing"
    fi
done
finish
