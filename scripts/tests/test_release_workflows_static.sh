#!/usr/bin/env sh
#
# RED-phase STATIC tests for 0056 C2 (relock.yml), C5 (security-digest.yml) and
# C3 (.github/dependabot.yml).
#
# GitHub Actions / Dependabot cannot run locally, so these tests read the
# committed YAML and assert the structural facts the LLD §5 C2/C3/C5 + §0
# re-scope + audit M2 require. They assert ONLY the desired end-state.
#
# Asserted contract:
#   C2 relock.yml (LLD §5 C2; §0 re-scope):
#     - workflow_dispatch present AND NO schedule:/cron: (dispatch-ONLY — the
#       dead-cron common-mode blind spot is designed out for a solo repo).
#     - uses the ./.github/actions/setup-pinned-uv composite (single-source uv).
#     - runs `make freeze-deps UPGRADE=1`.
#     - opens a PR via peter-evans/create-pull-request (SHA-pinned) on the FIXED
#       rolling branch `chore/relock-agents` (no churn, idempotent).
#     - permissions: contents: write + pull-requests: write (and NO id-token).
#     - concurrency: relock (serialize racing dispatches).
#     - SELF-RUNS scripts/check-lockfile.sh (R5: default-token PRs don't trigger
#       C1, so the relock job validates the lockfile itself).
#   C5 security-digest.yml (LLD §5 C5; M2):
#     - workflow_dispatch present AND NO schedule:/cron:.
#     - runs pip-audit and writes a summary to $GITHUB_STEP_SUMMARY.
#     - permissions: issues: write (for the tracking issue); NO id-token.
#     - concurrency: security-digest.
#     - a comment noting the Dependabot-alerts read needs a PAT/App secret (M2 —
#       the default GITHUB_TOKEN cannot read /dependabot/alerts).
#   C3 dependabot.yml (LLD §5 C3):
#     - version: 2 and parses as YAML (best-effort; degrades if no parser).
#     - DISABLES pip: contains NO `package-ecosystem: "pip"` (and no uv) entry —
#       neither a version nor a security updater can touch the lockfile.
#     - ENABLES github-actions + npm + gomod ecosystems.
#   ALL workflows: every third-party `uses:` is SHA-pinned (@<40-hex> # vN);
#   the in-repo composite `./.github/actions/...` is exempt.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final "N passed, M failed" line, exit 1 on any FAIL.
# Tiny functions (cyclomatic < 5), DRY, no bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
RELOCK_YML="$REPO_ROOT/.github/workflows/relock.yml"
DIGEST_YML="$REPO_ROOT/.github/workflows/security-digest.yml"
DEPENDABOT_YML="$REPO_ROOT/.github/dependabot.yml"

SHA_PIN_RE='@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]'

# dispatch_only_ok <file> — print "" if <file> has workflow_dispatch AND no
# schedule:/cron:, else a reason string. DRY helper for C2 + C5.
dispatch_only_ok() {
    _f=$1
    _d=""
    grep -Eq 'workflow_dispatch' "$_f" || _d="$_d no workflow_dispatch trigger;"
    grep -Eq '^[[:space:]]*schedule:' "$_f" && _d="$_d has a schedule: trigger (must be dispatch-only, §0);"
    grep -Eq '(^|[[:space:]])cron:' "$_f" && _d="$_d has a cron: schedule (must be dispatch-only, §0);"
    printf '%s' "$_d"
}

# unpinned_uses <file> — print any third-party `uses:` line in <file> that is
# NOT SHA-pinned (the in-repo ./.github/actions/ composite is exempt). Empty if
# all are pinned. DRY helper used by every workflow case.
unpinned_uses() {
    grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$1" \
        | grep '@' \
        | grep -v './.github/actions/' \
        | grep -Ev "$SHA_PIN_RE" || true
}

# ===========================================================================
# C2 — relock.yml
# ===========================================================================
test_relock_dispatch_only() {
    name="c2-relock-is-workflow_dispatch-only-no-cron"
    require_file_or_bail "$name" "$RELOCK_YML"
    _d=$(dispatch_only_ok "$RELOCK_YML")
    if [ -z "$_d" ]; then pass "$name"; else fail "$name" "$_d"; fi
}
test_relock_dispatch_only

test_relock_mechanism() {
    name="c2-relock-mechanism-composite-freeze-and-pr"
    require_file_or_bail "$name" "$RELOCK_YML"
    detail=""
    grep -Eq 'uses:[[:space:]]*\./\.github/actions/setup-pinned-uv' "$RELOCK_YML" \
        || detail="$detail does not use the setup-pinned-uv composite;"
    grep -Eq 'make[[:space:]]+freeze-deps[[:space:]]+UPGRADE=1' "$RELOCK_YML" \
        || detail="$detail does not run 'make freeze-deps UPGRADE=1';"
    grep -q 'peter-evans/create-pull-request' "$RELOCK_YML" \
        || detail="$detail does not open a PR via peter-evans/create-pull-request;"
    grep -q 'chore/relock-agents' "$RELOCK_YML" \
        || detail="$detail does not target the fixed branch chore/relock-agents;"
    grep -q 'check-lockfile.sh' "$RELOCK_YML" \
        || detail="$detail does not self-run check-lockfile.sh (R5);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_relock_mechanism

test_relock_perms_and_concurrency() {
    name="c2-relock-least-priv-perms-and-concurrency"
    require_file_or_bail "$name" "$RELOCK_YML"
    detail=""
    grep -Eq 'contents:[[:space:]]*write' "$RELOCK_YML" \
        || detail="$detail missing contents: write;"
    grep -Eq 'pull-requests:[[:space:]]*write' "$RELOCK_YML" \
        || detail="$detail missing pull-requests: write;"
    grep -Eq 'id-token:' "$RELOCK_YML" \
        && detail="$detail grants id-token (no signing scope allowed);"
    grep -Eq '^[[:space:]]*concurrency:' "$RELOCK_YML" \
        || detail="$detail no concurrency: group (races must serialize);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_relock_perms_and_concurrency

test_relock_sha_pins() {
    name="c2-relock-actions-sha-pinned"
    require_file_or_bail "$name" "$RELOCK_YML"
    _bad=$(unpinned_uses "$RELOCK_YML")
    if [ -z "$_bad" ]; then pass "$name"; else fail "$name" "unpinned: $(printf '%s' "$_bad" | tr '\n' '|')"; fi
}
test_relock_sha_pins

# ===========================================================================
# C5 — security-digest.yml
# ===========================================================================
test_digest_dispatch_only() {
    name="c5-digest-is-workflow_dispatch-only-no-cron"
    require_file_or_bail "$name" "$DIGEST_YML"
    _d=$(dispatch_only_ok "$DIGEST_YML")
    if [ -z "$_d" ]; then pass "$name"; else fail "$name" "$_d"; fi
}
test_digest_dispatch_only

test_digest_mechanism() {
    name="c5-digest-pip-audit-summary-and-pat-note"
    require_file_or_bail "$name" "$DIGEST_YML"
    detail=""
    grep -q 'pip-audit' "$DIGEST_YML" \
        || detail="$detail does not run pip-audit;"
    grep -q 'GITHUB_STEP_SUMMARY' "$DIGEST_YML" \
        || detail="$detail does not write to \$GITHUB_STEP_SUMMARY;"
    # M2: a comment must note the alert read needs a PAT/App secret.
    grep -Eqi 'PAT|DEPENDABOT_ALERTS_TOKEN|personal access token|App token' "$DIGEST_YML" \
        || detail="$detail no comment that the Dependabot-alerts read needs a PAT secret (M2);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_digest_mechanism

test_digest_perms_and_concurrency() {
    name="c5-digest-issues-write-and-concurrency"
    require_file_or_bail "$name" "$DIGEST_YML"
    detail=""
    grep -Eq 'issues:[[:space:]]*write' "$DIGEST_YML" \
        || detail="$detail missing issues: write;"
    grep -Eq 'id-token:' "$DIGEST_YML" \
        && detail="$detail grants id-token (no signing scope allowed);"
    grep -Eq '^[[:space:]]*concurrency:' "$DIGEST_YML" \
        || detail="$detail no concurrency: group;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_digest_perms_and_concurrency

test_digest_sha_pins() {
    name="c5-digest-actions-sha-pinned"
    require_file_or_bail "$name" "$DIGEST_YML"
    _bad=$(unpinned_uses "$DIGEST_YML")
    if [ -z "$_bad" ]; then pass "$name"; else fail "$name" "unpinned: $(printf '%s' "$_bad" | tr '\n' '|')"; fi
}
test_digest_sha_pins

# ===========================================================================
# C3 — dependabot.yml
# ===========================================================================
test_dependabot_disables_pip() {
    name="c3-dependabot-disables-pip-entirely"
    require_file_or_bail "$name" "$DEPENDABOT_YML"
    detail=""
    grep -Eq 'version:[[:space:]]*2' "$DEPENDABOT_YML" \
        || detail="$detail missing 'version: 2';"
    # No pip/uv updater of any kind (version OR security) may touch the lockfile.
    grep -Eqi 'package-ecosystem:[[:space:]]*.?(pip|uv)' "$DEPENDABOT_YML" \
        && detail="$detail declares a pip/uv updater (must have NONE — lockfile owned by C2);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_dependabot_disables_pip

test_dependabot_enables_safe_ecosystems() {
    name="c3-dependabot-enables-github-actions-npm-gomod"
    require_file_or_bail "$name" "$DEPENDABOT_YML"
    detail=""
    grep -Eqi 'package-ecosystem:[[:space:]]*.?github-actions' "$DEPENDABOT_YML" \
        || detail="$detail no github-actions ecosystem (needed to maintain SHA pins);"
    grep -Eqi 'package-ecosystem:[[:space:]]*.?npm' "$DEPENDABOT_YML" \
        || detail="$detail no npm ecosystem (frontend);"
    grep -Eqi 'package-ecosystem:[[:space:]]*.?gomod' "$DEPENDABOT_YML" \
        || detail="$detail no gomod ecosystem (backend);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_dependabot_enables_safe_ecosystems

# TEST — dependabot.yml is valid YAML. Best-effort: prefer a real parser, else
# degrade to a structural sanity check + a NOTE (no yamllint/python in CI shell
# must not turn this into a false failure).
test_dependabot_parses() {
    name="c3-dependabot-is-valid-yaml"
    require_file_or_bail "$name" "$DEPENDABOT_YML"
    if command -v yamllint >/dev/null 2>&1; then
        if yamllint -d relaxed "$DEPENDABOT_YML" >/dev/null 2>&1; then
            pass "$name"
        else
            fail "$name" "yamllint rejected dependabot.yml: $(yamllint -d relaxed "$DEPENDABOT_YML" 2>&1 | tr '\n' ' ')"
        fi
    elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
        if python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$DEPENDABOT_YML" >/dev/null 2>&1; then
            pass "$name"
        else
            fail "$name" "PyYAML failed to parse dependabot.yml: $(python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$DEPENDABOT_YML" 2>&1 | tr '\n' ' ')"
        fi
    else
        # No YAML parser available — degrade to a tab-character check (tabs are
        # illegal in YAML indentation) and PASS with a note rather than a false RED.
        if grep -Pq '\t' "$DEPENDABOT_YML" 2>/dev/null; then
            fail "$name" "dependabot.yml contains TAB indentation (illegal YAML)"
        else
            pass "$name (NOTE: no yamllint/PyYAML — structural tab-check only)"
        fi
    fi
}
test_dependabot_parses

# ---------------------------------------------------------------------------
# Tally.
# ---------------------------------------------------------------------------
finish
