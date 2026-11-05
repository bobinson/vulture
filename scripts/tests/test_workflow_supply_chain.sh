#!/usr/bin/env sh
#
# Static guards for the release supply chain (feature 0102).
#
# GitHub Actions cannot run locally, so these read the committed workflows and
# assert the structure that keeps the signing identity and the release upload
# away from third-party tooling:
#   S0  release.yml has exactly the jobs lint, build-frontend, build-binary,
#       scan, sign and release (a parse that found no job would pass S5-S7
#       vacuously)
#   S1  self-test of the pipe-to-shell matcher (6 positives, 5 negatives), so
#       S2 cannot pass vacuously
#   S2  no workflow or composite action pipes curl/wget into a shell or python
#   S3  every third-party `uses:` in every workflow and composite action is
#       SHA-pinned
#   S4  release.yml: workflow-level permissions exist and grant no write scope
#   S5  release.yml: every job declares its own permissions
#   S6  release.yml: id-token: write only in the job that signs, and that job
#       runs no checkout and no tooling
#   S7  release.yml: contents: write only in the `gh release` job, which runs
#       no tooling
#   S8  release.yml: every actions/checkout sets persist-credentials: false
#   S9  release.yml: trivy comes from scripts/install-trivy.sh, never from the
#       upstream installer script, and scripts/trivy-shas-$TRIVY_VERSION.txt
#       pins the Linux-64bit asset
#   S10 release.yml: build-frontend, whose output is embedded in the signed
#       tarball, runs only `npm ci`, `npm run build` and the checkout,
#       setup-node and upload-artifact actions
# plus a self-test of lib.sh's job_block, which S0 and S5-S10 read jobs with.
#
# Usage: sh scripts/tests/test_workflow_supply_chain.sh [repo-root]
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=${1:-$(repo_root "$0")}
WF="$REPO_ROOT/.github/workflows"
RELEASE_YML="$WF/release.yml"

# curl/wget output reaching a shell or python: a pipe (optionally through
# sudo), process substitution, or `sh -c "$(curl ...)"`.
PIPE_SH_RE='(curl|wget)[^;#]*\|[[:space:]]*(sudo[[:space:]]+(-[A-Za-z]+[[:space:]]+)*)?((ba|z|da|k)?sh|python[0-9.]*)([[:space:];]|$)|<\([[:space:]]*(curl|wget)|(sh|bash|eval)[[:space:]]+(-c[[:space:]]+)?["'"'"']?\$\([[:space:]]*(curl|wget)'
# What a privileged job must not run: a checkout (repository code), a
# downloader, a package manager or installer, or a scanner.
TOOLING_RE='actions/checkout|curl[[:space:]]|wget[[:space:]]|pip[0-9]*[[:space:]]+install|npm[[:space:]]|npx[[:space:]]|brew[[:space:]]|go[[:space:]]+install|apt-get|trivy|syft'

# has <text> <ere> — true when some line of <text> matches <ere>.
has() { printf '%s\n' "$1" | grep -Eq "$2"; }

# header <file> — the workflow-level lines (before `jobs:`), comments stripped.
header() { noncomment "$1" | awk '/^jobs:/ { exit } { print }'; }

# job_names <file> — the ids of the jobs under `jobs:`, in file order.
job_names() {
    noncomment "$1" | awk '/^jobs:/ { f = 1; next } f && /^[^[:space:]]/ { f = 0 }
        f && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { n = $1; sub(/:$/, "", n); print n }'
}

# each_job <fn> — run <fn> <job> for every release.yml job.
each_job() {
    for _ej in $(job_names "$RELEASE_YML"); do "$1" "$_ej"; done
}

# each_workflow <fn> — run <fn> <file> for every workflow and composite action.
each_workflow() {
    for _ew in "$WF"/*.yml "$REPO_ROOT"/.github/actions/*/action.yml; do
        [ ! -f "$_ew" ] || "$1" "$_ew"
    done
}

# joined <file> — non-comment lines with shell continuations joined (a trailing
# `\`, or a trailing `|` that is not a YAML block-scalar indicator), printed as
# "<name>:<first line>: <text>", so a pipe split across lines is still seen.
joined() {
    awk -v f="${1##*/}" '
        /^[[:space:]]*#/ { next }
        { sub(/[[:space:]]#.*$/, ""); if (buf == "") start = NR; buf = buf " " $0 }
        /\\[[:space:]]*$/ { sub(/\\[[:space:]]*$/, "", buf); next }
        /\|[[:space:]]*$/ && $0 !~ /:[[:space:]]*\|[-+]?[[:space:]]*$/ { next }
        { print f ":" start ":" buf; buf = "" }' "$1"
}

# pipe_hits <file> — the joined lines of <file> that pipe a download to a shell.
pipe_hits() { joined "$1" | grep -E "$PIPE_SH_RE" | cut -c1-160; }

# pin_misses <file> — "<path>: <line>" for each unpinned `uses:` in <file>.
pin_misses() {
    unpinned_uses "$1" | sed -e 's/^[[:space:]]*//' -e "s#^#${1#"$REPO_ROOT"/}: #"
}

# privileged_tooling <job> <block> — name the tooling a privileged job runs.
privileged_tooling() {
    _pt=$(printf '%s\n' "$2" | grep -Eo "$TOOLING_RE" | LC_ALL=C sort -u | tr '\n' ',')
    [ -z "$_pt" ] || printf ' %s:privileged-job-runs-tooling(%s);' "$1" "$_pt"
}

# signing_key <block> — "token", "sign", "tokensign" or "" for whether <block>
# holds id-token: write and whether it runs cosign sign-blob.
signing_key() {
    has "$1" 'id-token:[[:space:]]*write' && printf token
    has "$1" 'cosign[[:space:]]+sign-blob' && printf sign
}

# signing_violation <job> — why <job>'s OIDC token use is unsafe ("" if not).
signing_violation() {
    _sv=$(job_block "$RELEASE_YML" "$1")
    case $(signing_key "$_sv") in
        sign) printf ' %s:signs-without-own-id-token;' "$1" ;;
        token) printf ' %s:id-token-without-signing;' "$1"; privileged_tooling "$1" "$_sv" ;;
        tokensign) privileged_tooling "$1" "$_sv" ;;
    esac
}

# publish_violation <job> — why <job>'s contents: write is unsafe ("" if not).
publish_violation() {
    _pv=$(job_block "$RELEASE_YML" "$1")
    has "$_pv" 'contents:[[:space:]]*write' || return 0
    has "$_pv" 'gh[[:space:]]+release' || printf ' %s:contents-write-without-publish;' "$1"
    privileged_tooling "$1" "$_pv"
}

# perms_missing <job> — print <job> when it declares no job-level permissions.
perms_missing() {
    has "$(job_block "$RELEASE_YML" "$1")" '^    permissions:' || printf ' %s' "$1"
}

# checkouts_persisting <file> — "N," for each actions/checkout step (by line)
# that does not set persist-credentials: false; a comment never satisfies it.
checkouts_persisting() {
    awk '
        function flush() { if (pend) printf "%d,", pl; pend = 0 }
        /^[[:space:]]*#/ { next }
        { sub(/[[:space:]]#.*$/, "") }
        /uses:[[:space:]]*actions\/checkout@/ { flush(); pend = 1; pl = NR; next }
        pend && /^[[:space:]]*- / { flush() }
        pend && /persist-credentials:[[:space:]]*false/ { pend = 0 }
        END { flush() }' "$1"
}

# trivy_version <text> — the workflow-local TRIVY_VERSION in <text>, the
# comment-stripped release.yml ("" if none).
trivy_version() {
    printf '%s\n' "$1" \
        | sed -n "s/^[[:space:]]*TRIVY_VERSION:[[:space:]]*['\"]\{0,1\}\(v[0-9.]*\)['\"]\{0,1\}[[:space:]]*\$/\1/p" \
        | head -n 1
}

# pins_linux_asset <version> — scripts/trivy-shas-<version>.txt has a 64-hex
# line for the Linux-64bit asset (the release runners' platform).
pins_linux_asset() {
    awk -v f="trivy_${1#v}_Linux-64bit.tar.gz" \
        '$2 == f && length($1) == 64 && $1 !~ /[^0-9a-f]/ { ok = 1 } END { exit !ok }' \
        "$REPO_ROOT/scripts/trivy-shas-$1.txt" 2>/dev/null
}

# step_values <block> <key> — the values of the single-line `<key>:` entries in
# <block> ("- run: x" and "run: x" alike), one per line.
step_values() {
    printf '%s\n' "$1" | sed -n "s/^[[:space:]]*\(- \)\{0,1\}$2:[[:space:]]*//p"
}

# frontend_step_drift <block> — how build-frontend's steps differ from the
# allowed set ("" when they match exactly).
frontend_step_drift() {
    _fr=$(step_values "$1" run | LC_ALL=C sort | tr '\n' '|')
    _fu=$(step_values "$1" uses | sed 's/@.*//' | LC_ALL=C sort | tr '\n' '|')
    [ "$_fr" = "npm ci|npm run build|" ] || printf " run steps '%s' want 'npm ci|npm run build|';" "$_fr"
    [ "$_fu" = "actions/checkout|actions/setup-node|actions/upload-artifact|" ] || printf " actions '%s';" "$_fu"
}

# ---------------------------------------------------------------------------
# lib.sh's job_block is what S0 and S5-S10 see of a job: pin its edges.
# ---------------------------------------------------------------------------
lib_job_block_selftest() {
    make_sandbox
    _y="$SANDBOX/wf.yml"
    cat > "$_y" <<'YAML'
name: fixture
permissions: {}
jobs:
  alpha:
    runs-on: x # trailing comment
    # whole-line comment
    steps:
      - run: echo alpha
  beta:
    steps:
      - name: a nested key named like a job
        with:
          alpha: 1
on:
  push: {}
YAML
    _d=""
    [ "$(job_block "$_y" alpha)" = "$(printf '    runs-on: x\n    steps:\n      - run: echo alpha')" ] \
        || _d="$_d alpha: [$(job_block "$_y" alpha | tr '\n' '|')];"
    [ "$(job_block "$_y" beta)" = "$(printf '    steps:\n      - name: a nested key named like a job\n        with:\n          alpha: 1')" ] \
        || _d="$_d beta: [$(job_block "$_y" beta | tr '\n' '|')];"
    [ -z "$(job_block "$_y" gamma)" ] || _d="$_d a missing job has a body;"
    verdict lib-job-block-selftest "$_d"
}

s0_release_job_set() {
    _got=$(job_names "$RELEASE_YML" | LC_ALL=C sort | tr '\n' ' ')
    _want=$(printf '%s\n' lint build-frontend build-binary scan sign release | LC_ALL=C sort | tr '\n' ' ')
    _d=""
    [ "$_got" = "$_want" ] || _d="jobs '$_got' want '$_want'"
    verdict s0-release-job-set "$_d"
}

s1_detector_selftest() {
    _bad=""
    # shellcheck disable=SC2016 # the samples are literal shell text
    for _l in 'curl -sfL https://x/install.sh | sh -s -- -b /usr/local/bin' \
              'curl -fsSL x | sudo -E bash' 'wget -qO- x | python3 -' \
              'curl -fsSL x | tee i.log | sh' 'bash <(curl -fsSL x)' \
              'sh -c "$(curl -fsSL x)"'; do
        has "$_l" "$PIPE_SH_RE" || _bad="$_bad missed:[$_l]"
    done
    for _l in 'curl -fsSL -o t.tgz x && sha256sum -c sums' 'run: |' \
              'grep -E x f | sort' 'curl -s x | jq .tag_name' 'shellcheck install.sh'; do
        has "$_l" "$PIPE_SH_RE" && _bad="$_bad false-positive:[$_l]"
    done
    verdict s1-detector-selftest "$_bad"
}

s2_no_pipe_to_shell() {
    verdict s2-no-pipe-to-shell "$(each_workflow pipe_hits | tr '\n' '|')"
}

s3_actions_sha_pinned() {
    verdict s3-actions-sha-pinned "$(each_workflow pin_misses | tr '\n' '|')"
}

s4_workflow_perms_readonly() {
    _h=$(header "$RELEASE_YML")
    _d=""
    has "$_h" '^permissions:' || _d=" no workflow-level permissions;"
    _w=$(printf '%s\n' "$_h" | grep -E ':[[:space:]]*write' | tr -s ' ' | tr '\n' '|')
    [ -z "$_w" ] || _d="$_d workflow-level write grants:$_w"
    verdict s4-release-workflow-perms-readonly "$_d"
}

s5_each_job_declares_perms() {
    _m=$(each_job perms_missing)
    verdict s5-release-jobs-declare-perms "${_m:+no job-level permissions:$_m}"
}

s6_signing_isolated() {
    verdict s6-release-signing-isolated "$(each_job signing_violation)"
}

s7_publish_isolated() {
    verdict s7-release-publish-isolated "$(each_job publish_violation)"
}

s8_checkout_no_persist() {
    _l=$(checkouts_persisting "$RELEASE_YML")
    verdict s8-release-checkout-no-persist "${_l:+checkout without persist-credentials: false at release.yml lines $_l}"
}

s9_trivy_pinned() {
    _y=$(noncomment "$RELEASE_YML")
    _v=$(trivy_version "$_y")
    _d=""
    has "$_y" 'raw\.githubusercontent\.com|get\.trivy\.dev|contrib/install\.sh' && _d=" fetches the upstream installer script;"
    has "$_y" 'scripts/install-trivy\.sh' || _d="$_d does not use scripts/install-trivy.sh;"
    pins_linux_asset "$_v" || _d="$_d no committed SHA-256 pin for trivy_${_v#v}_Linux-64bit.tar.gz (TRIVY_VERSION='$_v');"
    verdict s9-release-trivy-pinned "$_d"
}

# The job whose output is embedded in the signed tarball runs only
# lockfile-pinned npm (ci + build) and three first-party actions: any other
# step (npx, a scanner, another action) could rewrite frontend/dist first.
s10_build_frontend_minimal() {
    _b=$(job_block "$RELEASE_YML" build-frontend)
    _d=$(frontend_step_drift "$_b")
    [ -n "$_b" ] || _d=" no build-frontend job;$_d"
    has "$_b" '(^|[^A-Za-z0-9_-])npx([[:space:]]|$)' && _d="$_d runs npx;"
    verdict s10-build-frontend-minimal "$_d"
}

lib_job_block_selftest
s0_release_job_set
s1_detector_selftest
s2_no_pipe_to_shell
s3_actions_sha_pinned
s4_workflow_perms_readonly
s5_each_job_declares_perms
s6_signing_isolated
s7_publish_isolated
s8_checkout_no_persist
s9_trivy_pinned
s10_build_frontend_minimal
finish
