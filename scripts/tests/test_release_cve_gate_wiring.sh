#!/usr/bin/env sh
#
# Static guards for the release CVE gate (feature 0102).
#
# release.yml's `scan` job runs scripts/release-cve-gate.sh over the built
# tarballs before any step that runs floating code, and `sign` signs only after
# `scan` passed. GitHub Actions cannot run locally, so these read the committed
# workflows, the gate script and .trivyignore, and assert what keeps the gate
# blocking:
#   S11 the gate's wiring
#     s11-gate-step           `scan` has exactly one gate step, and its run: is
#                             exactly GATE_RUN
#     s11-gate-blocking       neither the gate step nor `scan` has
#                             continue-on-error, and the gate step has no if:
#     s11-gate-first          no setup-node, npm/npx, pip or syft step precedes
#                             the gate in `scan`; the expected sums come from
#                             toJSON(needs.build-binary.outputs) through the
#                             same jq program as `sign`, so the verdict is about
#                             the bytes `sign` signs
#     s11-sign-needs-scan     `sign` needs `scan`; neither `sign` nor `release`
#                             has an if:
#     s11-reports-uploaded    the scan-reports upload covers the gate's report
#                             names (dist/<tarball>.vulns.json)
#     s11-no-trivy-fs         no workflow that handles tarballs runs `trivy fs`,
#                             which does not unpack an archive
#     s11-gate-no-skip-flags  the gate script passes none of --skip-db-update,
#                             --skip-dirs, --skip-files, --ignore-policy, --vex,
#                             --ignore-unfixed
#   S12 the waiver file (scripts/lib/trivyignore.sh, trivyignore_check <file>
#       <today>; the gate runs it at tag time, this suite at PR time)
#     s12-trivyignore-file    .trivyignore passes for today (UTC)
#     s12-selftest-entries    every non-blank line not starting with # is an
#                             entry `<ID> exp:YYYY-MM-DD # <reason>`: leading
#                             whitespace, tabs, a bare ID, a missing exp: and a
#                             missing reason are refused, also on a last line
#                             without a newline
#     s12-selftest-dates      exp: is a real calendar date (leap years included)
#     s12-selftest-90-days    exp: is at most 90 days after an injected today
#
# Usage: sh scripts/tests/test_release_cve_gate_wiring.sh [repo-root]
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=${1:-$(repo_root "$0")}
WF="$REPO_ROOT/.github/workflows"
RELEASE_YML="$WF/release.yml"
GATE="$REPO_ROOT/scripts/release-cve-gate.sh"
IGNORE_LIB="$REPO_ROOT/scripts/lib/trivyignore.sh"

# The gate step's whole run: line. The arguments are positional: the installed
# trivy, the downloaded tarballs, a fresh work dir, the waiver file and the
# build legs' digests.
# shellcheck disable=SC2016 # the $RUNNER_TEMP references are literal workflow text
GATE_RUN='scripts/release-cve-gate.sh "$RUNNER_TEMP/trivy-bin/trivy" dist "$RUNNER_TEMP/cve-gate" .trivyignore "$RUNNER_TEMP/expected.sha256"'
# A step that runs floating code: a node or python toolchain, npm/npx, pip, or
# a scanner other than the gate.
FLOATING_RE='actions/setup-node|actions/setup-python|sbom-action|(^|[^A-Za-z0-9_./-])(npx|npm|pipx|pip[0-9.]*|pip-audit|syft|audit-ci)([^A-Za-z0-9_-]|$)'
# What would let the gate pass while reading less.
SKIP_FLAGS_RE='--(skip-db-update|skip-dirs|skip-files|ignore-policy|vex|ignore-unfixed)'

make_sandbox

# steps <job block> — one line per step of the job, the step's lines joined
# with \037 (steps are the 6-space `- ` items; a shallower key ends the list).
steps() {
    printf '%s\n' "$1" | awk '
        { i = match($0, /[^ ]/) - 1 }
        i == 6 && /^      - / { if (s != "") print s; s = $0; next }
        i >= 0 && i < 6 { if (s != "") print s; s = ""; next }
        s != "" { s = s "\037" $0 }
        END { if (s != "") print s }'
}

# step_value <step> <key> — the value of <key> in <step>: the inline value, or
# the lines of a | or > block, trimmed and joined with newlines.
step_value() {
    printf '%s\n' "$1" | tr '\037' '\n' | awk -v k="$2" '
        r && /^[[:space:]]*$/ { next }
        r && match($0, /[^ ]/) - 1 > ki { v = v (v == "" ? "" : "\n") substr($0, RSTART); next }
        r { exit }
        $0 ~ "^[ -]*" k ":" {
            ki = match($0, k ":") - 1; v = substr($0, ki + length(k) + 2); sub(/^[[:space:]]+/, "", v)
            if (v ~ /^[|>][-+]?$/) { v = ""; r = 1; next }
            exit
        }
        END { print v }'
}

# gate_steps <steps> — the steps that run the gate script.
gate_steps() { printf '%s\n' "$1" | grep -F 'release-cve-gate.sh'; }

# floating_before_gate <steps> — the steps before the gate that run floating
# code, abridged.
floating_before_gate() {
    printf '%s\n' "$1" | awk -v re="$FLOATING_RE" '
        /release-cve-gate\.sh/ { exit }
        $0 ~ re { r = $0; gsub("\037", " ", r); gsub(/[[:space:]]+/, " ", r); print substr(r, 1, 90) }'
}

# jq_program <block> — the first single-quoted jq program over to_entries.
jq_program() { printf '%s\n' "$1" | grep -o "'to_entries[^']*'" | head -n 1; }

# needs_of <job block> — the jobs it needs, one per line.
needs_of() {
    printf '%s\n' "$1" | awk '
        /^    needs:/ { v = $0; sub(/^    needs:[[:space:]]*/, "", v); if (v != "") { print v; exit } n = 1; next }
        n && /^      - / { v = $0; sub(/^      - /, "", v); print v; next }
        n { exit }' | sed 's/[][,]/ /g' | tr -s ' ' '\n' | grep -v '^$'
}

# if_lines <job block> — any job- or step-level if:.
if_lines() { printf '%s\n' "$1" | grep -E '^[[:space:]]*(-[[:space:]]+)?if:'; }

# covers <glob lines> <path> — "yes" when one of the globs matches <path>.
covers() {
    printf '%s\n' "$1" | while IFS= read -r _g; do
        # shellcheck disable=SC2254 # each line is a glob on purpose
        case $2 in $_g) echo yes; break ;; esac
    done
}

# trivy_fs_on_tarballs <file> — "<file>:<line>" for each `trivy fs` in a
# workflow that names a .tar.gz/.tgz anywhere (comments ignored).
trivy_fs_on_tarballs() {
    awk -v f="${1#"$REPO_ROOT"/}" '
        /^[[:space:]]*#/ { next }
        { sub(/[[:space:]]#.*$/, "") }
        /trivy[[:space:]]+(fs|filesystem)([[:space:]]|$)/ { hits = hits " " f ":" NR }
        /\.(tar\.gz|tgz)/ { tb = 1 }
        END { if (hits != "" && tb) print hits ";" }' "$1"
}

# load_gate — read `scan` once, before the S11 cases: sets SCAN (the job
# block), SCAN_STEPS (its steps), GATE_STEP (the steps running the gate) and
# GATE_D ("" when there is exactly one gate step, else why not).
load_gate() {
    SCAN=$(job_block "$RELEASE_YML" scan)
    SCAN_STEPS=$(steps "$SCAN")
    GATE_STEP=$(gate_steps "$SCAN_STEPS")
    _n=$(printf '%s' "$GATE_STEP" | grep -c .)
    GATE_D=""
    [ "$_n" -eq 1 ] || GATE_D=" $_n gate steps in scan, want 1;"
}

# lib_present <name> — fail <name> and return 1 when the waiver lib is absent.
lib_present() {
    [ -f "$IGNORE_LIB" ] && return 0
    fail "$1" "scripts/lib/trivyignore.sh is missing"
    return 1
}

# check_ignore <file> <today> — trivyignore_check, sourced in a subshell so the
# lib cannot change this suite's shell.
check_ignore() {
    # shellcheck source=/dev/null
    ( . "$IGNORE_LIB" && trivyignore_check "$1" "$2" )
}

# ignore_ok <content> <today> — trivyignore_check's verdict on a file holding
# <content> (printf %b escapes: \n, \t).
ignore_ok() {
    printf '%b' "$1" > "$SANDBOX/trivyignore"
    check_ignore "$SANDBOX/trivyignore" "$2" > /dev/null 2>&1
}

# accepts <today> <content>... / refuses <today> <content>... — a detail for
# every <content> judged the other way.
accepts() {
    _t=$1; shift
    for _c in "$@"; do ignore_ok "$_c" "$_t" || printf ' refused [%s] (today %s);' "$_c" "$_t"; done
}
refuses() {
    _t=$1; shift
    for _c in "$@"; do ! ignore_ok "$_c" "$_t" || printf ' accepted [%s] (today %s);' "$_c" "$_t"; done
}

s11_gate_step() {
    _d=$GATE_D
    _r=$(step_value "$GATE_STEP" run)
    [ -z "$GATE_STEP" ] || [ "$_r" = "$GATE_RUN" ] || _d="$_d run: is [$(printf '%s' "$_r" | tr '\n' '|')] want [$GATE_RUN];"
    verdict s11-gate-step "$_d"
}

s11_gate_blocking() {
    _d=$GATE_D
    _s=$(printf '%s\n' "$GATE_STEP" | tr '\037' '\n')
    printf '%s\n' "$SCAN" | grep -Eq '^    continue-on-error:' && _d="$_d scan has continue-on-error;"
    printf '%s\n' "$_s" | grep -q 'continue-on-error' && _d="$_d the gate step has continue-on-error;"
    [ -z "$(if_lines "$_s")" ] || _d="$_d the gate step has an if:;"
    verdict s11-gate-blocking "$_d"
}

s11_gate_first() {
    _d=$GATE_D
    [ -z "$GATE_STEP" ] || _d="$_d$(floating_before_gate "$SCAN_STEPS" | sed 's/^/ before the gate: /; s/$/;/' | tr -d '\n')"
    case $SCAN in
        *'toJSON(needs.build-binary.outputs)'*) ;;
        *) _d="$_d scan does not read toJSON(needs.build-binary.outputs);" ;;
    esac
    _want=$(jq_program "$(job_block "$RELEASE_YML" sign)")
    [ -n "$_want" ] && [ "$(jq_program "$SCAN")" = "$_want" ] \
        || _d="$_d scan's expected-sums jq program is not sign's;"
    verdict s11-gate-first "$_d"
}

s11_sign_needs_scan() {
    _sign=$(job_block "$RELEASE_YML" sign)
    _d=""
    [ -n "$_sign" ] || _d=" no sign job;"
    needs_of "$_sign" | grep -qx scan || _d="$_d sign does not need scan;"
    [ -z "$(if_lines "$_sign")" ] || _d="$_d sign has an if:;"
    [ -z "$(if_lines "$(job_block "$RELEASE_YML" release)")" ] || _d="$_d release has an if:;"
    verdict s11-sign-needs-scan "$_d"
}

s11_reports_uploaded() {
    _up=$(printf '%s\n' "$SCAN_STEPS" | grep -F 'upload-artifact' | grep -E 'name:[[:space:]]*scan-reports')
    _d=""
    [ -n "$_up" ] || _d=" scan uploads no scan-reports artifact;"
    [ -n "$(covers "$(step_value "$_up" path)" dist/vulture-v0.0.0-linux-amd64.vulns.json)" ] \
        || _d="$_d the scan-reports path does not cover dist/<tarball>.vulns.json;"
    verdict s11-reports-uploaded "$_d"
}

s11_no_trivy_fs() {
    _d=""
    for _f in "$WF"/*.yml "$REPO_ROOT"/.github/actions/*/action.yml; do
        [ ! -f "$_f" ] || _d="$_d$(trivy_fs_on_tarballs "$_f")"
    done
    verdict s11-no-trivy-fs "${_d:+ trivy fs in a workflow that handles tarballs:$_d}"
}

s11_gate_no_skip_flags() {
    if [ ! -f "$GATE" ]; then fail s11-gate-no-skip-flags "scripts/release-cve-gate.sh is missing"; return 0; fi
    _h=$(noncomment "$GATE" | grep -Eo -e "$SKIP_FLAGS_RE" | LC_ALL=C sort -u | tr '\n' ' ')
    verdict s11-gate-no-skip-flags "${_h:+ the gate passes $_h}"
}

s12_trivyignore_file() {
    lib_present s12-trivyignore-file || return 0
    _today=$(date -u +%F)
    _d=""
    if ! _o=$(check_ignore "$REPO_ROOT/.trivyignore" "$_today" 2>&1); then
        _d=" .trivyignore refused for $_today: $(printf '%s' "$_o" | head -c 300 | tr '\n' '|')"
    fi
    verdict s12-trivyignore-file "$_d"
}

s12_selftest_entries() {
    lib_present s12-selftest-entries || return 0
    _ok='CVE-2026-0001 exp:2026-11-28 # a reason'
    _d=$(accepts 2026-10-29 "$_ok\n" '' '# comments only\n\n#\n' \
        "# header\n\n$_ok\n\nGHSA-aaaa-bbbb-cccc exp:2026-12-01 # another reason\n")
    _d="$_d$(refuses 2026-10-29 " $_ok\n" "\t$_ok\n" \
        'CVE-2026-0001\texp:2026-11-28 # a tab separator\n' \
        'CVE-2026-0001 exp:2026-11-28\t# a tab before the reason\n' \
        'CVE-2026-0001\n' 'CVE-2026-0001 # no expiry\n' 'CVE-2026-0001 exp:2026-11-28\n' \
        'CVE-2026-0001 exp:2026-11-28 #\n' 'CVE-2026-0001 exp:2026-11-28 #   \n' \
        "$_ok\nCVE-2026-0002")"
    verdict s12-selftest-entries "$_d"
}

s12_selftest_dates() {
    lib_present s12-selftest-dates || return 0
    _d=$(accepts 2028-01-15 'CVE-2026-0001 exp:2028-02-29 # leap year\n')
    _d="$_d$(accepts 2000-01-15 'CVE-2026-0001 exp:2000-02-29 # 400-year leap\n')"
    _d="$_d$(accepts 2026-10-29 'CVE-2026-0001 exp:2026-11-30 # r\n' 'CVE-2026-0001 exp:2026-12-31 # r\n')"
    _d="$_d$(refuses 2027-01-15 'CVE-2026-0001 exp:2027-02-29 # not a leap year\n')"
    _d="$_d$(refuses 2100-01-15 'CVE-2026-0001 exp:2100-02-29 # century, not a leap year\n')"
    _d="$_d$(refuses 2026-10-29 'CVE-2026-0001 exp:2026-11-31 # r\n' 'CVE-2026-0001 exp:2026-13-01 # r\n' \
        'CVE-2026-0001 exp:2026-11-00 # r\n' 'CVE-2026-0001 exp:2026-00-15 # r\n' \
        'CVE-2026-0001 exp:2026-11-5 # r\n' 'CVE-2026-0001 exp:26-11-05 # r\n' \
        'CVE-2026-0001 exp:2026/11/05 # r\n' 'CVE-2026-0001 exp:2026-11-05x # r\n')"
    verdict s12-selftest-dates "$_d"
}

# day 90 is accepted and day 91 refused, across a year end, a 28- and a 29-day
# February, a century and a 400-year leap.
s12_selftest_90_days() {
    lib_present s12-selftest-90-days || return 0
    _d=""
    for _w in '2026-10-29 2027-01-27 2027-01-28' '2026-12-15 2027-03-15 2027-03-16' \
              '2027-12-15 2028-03-14 2028-03-15' '2099-12-15 2100-03-15 2100-03-16' \
              '1999-12-15 2000-03-14 2000-03-15' '2026-12-31 2027-03-31 2027-04-01'; do
        # shellcheck disable=SC2086 # split the three dates on purpose
        set -- $_w
        _d="$_d$(accepts "$1" "CVE-2026-0001 exp:$2 # day 90\n")$(refuses "$1" "CVE-2026-0001 exp:$3 # day 91\n")"
    done
    verdict s12-selftest-90-days "$_d"
}

load_gate
s11_gate_step
s11_gate_blocking
s11_gate_first
s11_sign_needs_scan
s11_reports_uploaded
s11_no_trivy_fs
s11_gate_no_skip_flags
s12_trivyignore_file
s12_selftest_entries
s12_selftest_dates
s12_selftest_90_days
finish
