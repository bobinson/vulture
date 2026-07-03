#!/usr/bin/env sh
#
# RED-phase STATIC tests for 0056 C1 — the CI lockfile-freshness gate
# (`.github/workflows/lockfile.yml`) and the `setup-pinned-uv` composite action
# it depends on.
#
# These tests are STATIC: GitHub Actions cannot run locally, so they read the
# committed YAML and assert the structural facts the LLD §5 C1 + audit M3/M4
# require. They assert ONLY the desired end-state; they never implement it.
#
# Asserted contract (LLD 0056 §5 C1, §12, §13; audit M3/M4):
#   1) SEPARATE WORKFLOW — C1 lives in its OWN `.github/workflows/lockfile.yml`,
#      NOT a job grafted into ci.yml (M4: ci.yml has no on.paths, so it cannot
#      get C1's path-scoping). The file must exist and be its own workflow.
#   2) PATH GATE AT on.pull_request.paths — gated by a workflow-level
#      `on.pull_request.paths` filter (NOT a job-level contains()), and the paths
#      must include the GENERATOR INPUTS (gen-lockfile.sh, check-lockfile.sh,
#      lockfile-constraints.txt, uv-version.sh / lock-date.txt) so a PR editing
#      only the generator — with no agents/** file — is still gated.
#   3) USES THE COMPOSITE ACTION — the job uses ./.github/actions/setup-pinned-uv
#      (the single-source uv step), not an inline hardcoded uv version.
#   4) RUNS check-lockfile.sh — the gate re-derives + diffs via
#      scripts/check-lockfile.sh.
#   5) LEAST PRIVILEGE — permissions: contents: read (no write, no secrets), and
#      it is `pull_request`, NOT `pull_request_target` (the fork-PR foot-gun).
#   6) SHA-PINNED ACTIONS — every `uses:` that points at a third-party action is
#      pinned to a 40-hex commit SHA with a `# vN` comment (repo convention).
#   7) ADVISORY-FIRST — shipped advisory (continue-on-error: true) for the soak,
#      with a TODO to flip it to enforcing (LLD §7 rollout step 1).
#   8) setup-pinned-uv COMPOSITE ACTION (M3) — fetches the base ref content
#      explicitly (`git fetch --depth=1 origin main` — pinned to the LITERAL
#      `main`, never the attacker-controllable github.base_ref), reads the pin
#      from `FETCH_HEAD:scripts/uv-version.sh` (`git show FETCH_HEAD:...`),
#      validates `^[0-9]+\.[0-9]+\.[0-9]+$` and FAILS the step on a mismatch (no
#      silent default-to-latest), then hands the validated version to a
#      SHA-pinned astral-sh/setup-uv.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final "N passed, M failed" line, exit 1 on any FAIL.
# Tiny functions (cyclomatic < 5), DRY, no bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

# ---------------------------------------------------------------------------
# Files under test.
# ---------------------------------------------------------------------------
REPO_ROOT=$(repo_root "$0")
LOCKFILE_YML="$REPO_ROOT/.github/workflows/lockfile.yml"
ACTION_YML="$REPO_ROOT/.github/actions/setup-pinned-uv/action.yml"
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"

# A 40-char hex SHA followed by a `# vN` version comment — the repo's pinning
# convention (e.g. `actions/checkout@34e1...8d5 # v4`).
SHA_PIN_RE='@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]'

# noncomment <file> — print <file> with YAML comments stripped: drop whole-line
# comments (first non-blank char is `#`) and strip inline trailing ` #...`. The
# NEGATIVE guards below (must-NOT-use pull_request_target / github.base_ref /
# contains()) run against this so a comment that NAMES the forbidden token (to
# explain it is forbidden) does not trip the guard. This narrows the guards to
# real YAML usage; it does not relax the contract.
noncomment() {
    sed -e 's/[[:space:]]#.*$//' -e '/^[[:space:]]*#/d' "$1"
}

# ---------------------------------------------------------------------------
# TEST 1 — lockfile.yml exists as a SEPARATE workflow (M4).
# It must be its own file under .github/workflows/, and the C1 gate must NOT be
# a job in ci.yml (ci.yml lacks on.paths, so it cannot path-scope C1).
# ---------------------------------------------------------------------------
test_separate_workflow() {
    name="c1-is-a-separate-lockfile-workflow"
    require_file_or_bail "$name" "$LOCKFILE_YML"
    # Negative guard: ci.yml must not carry the lockfile gate (no check-lockfile.sh
    # reference there) — C1 belongs in its own file with its own on.paths.
    if [ -f "$CI_YML" ] && grep -q 'check-lockfile.sh' "$CI_YML"; then
        fail "$name" "the lockfile gate leaked into ci.yml (check-lockfile.sh referenced there); C1 must be a separate lockfile.yml (M4)"
        return
    fi
    pass "$name"
}
test_separate_workflow

# ---------------------------------------------------------------------------
# TEST 2 — triggered on pull_request (NOT pull_request_target) with an
# on.pull_request.paths gate that INCLUDES the generator inputs.
# ---------------------------------------------------------------------------
test_path_gate_includes_generator_inputs() {
    name="c1-on-pull_request-paths-includes-generator-inputs"
    require_file_or_bail "$name" "$LOCKFILE_YML"
    detail=""
    # pull_request, never pull_request_target (the fork-secret exfil foot-gun).
    grep -Eq '^[[:space:]]*pull_request:' "$LOCKFILE_YML" \
        || detail="$detail no on.pull_request trigger;"
    noncomment "$LOCKFILE_YML" | grep -Eq 'pull_request_target' \
        && detail="$detail uses pull_request_target (fork-PR foot-gun; must be pull_request);"
    # A workflow-level paths filter must exist (NOT a job-level contains()).
    grep -Eq '^[[:space:]]*paths:' "$LOCKFILE_YML" \
        || detail="$detail no on.pull_request.paths filter;"
    noncomment "$LOCKFILE_YML" | grep -Eq 'contains\(' \
        && detail="$detail uses a job-level contains() filter (must be on.paths);"
    # The paths MUST include the generator inputs (a PR editing only the
    # generator, with no agents/** file, must still be gated).
    grep -q 'gen-lockfile.sh' "$LOCKFILE_YML" \
        || detail="$detail paths omit scripts/gen-lockfile.sh;"
    grep -q 'check-lockfile.sh' "$LOCKFILE_YML" \
        || detail="$detail paths omit scripts/check-lockfile.sh;"
    grep -q 'lockfile-constraints.txt' "$LOCKFILE_YML" \
        || detail="$detail paths omit agents/lockfile-constraints.txt;"
    grep -Eq "agents/\\*\\*|'agents/" "$LOCKFILE_YML" \
        || detail="$detail paths omit agents/**;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_path_gate_includes_generator_inputs

# ---------------------------------------------------------------------------
# TEST 3 — the job USES the setup-pinned-uv composite action and RUNS
# check-lockfile.sh (the single-source uv step + the actual gate).
# ---------------------------------------------------------------------------
test_uses_composite_and_runs_check() {
    name="c1-uses-composite-action-and-runs-check-lockfile"
    require_file_or_bail "$name" "$LOCKFILE_YML"
    detail=""
    grep -Eq 'uses:[[:space:]]*\./\.github/actions/setup-pinned-uv' "$LOCKFILE_YML" \
        || detail="$detail does not use ./.github/actions/setup-pinned-uv;"
    grep -q 'check-lockfile.sh' "$LOCKFILE_YML" \
        || detail="$detail does not run scripts/check-lockfile.sh;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_uses_composite_and_runs_check

# ---------------------------------------------------------------------------
# TEST 4 — least privilege: permissions: contents: read, and every third-party
# `uses:` is SHA-pinned. (The local composite `./.github/actions/...` is exempt
# from SHA-pinning — it is in-repo, not a third-party ref.)
# ---------------------------------------------------------------------------
test_least_priv_and_sha_pins() {
    name="c1-contents-read-and-sha-pinned-actions"
    require_file_or_bail "$name" "$LOCKFILE_YML"
    detail=""
    grep -Eq 'permissions:|contents:[[:space:]]*read' "$LOCKFILE_YML" \
        || detail="$detail no permissions block;"
    grep -Eq 'contents:[[:space:]]*read' "$LOCKFILE_YML" \
        || detail="$detail contents is not read-only;"
    grep -Eq 'contents:[[:space:]]*write|packages:[[:space:]]*write|id-token:' "$LOCKFILE_YML" \
        && detail="$detail grants a write/id-token scope (must be contents:read only);"
    # Every third-party `uses:` (one with an `@`) must be SHA-pinned.
    _bad=$(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$LOCKFILE_YML" \
        | grep '@' \
        | grep -v './.github/actions/' \
        | grep -Ev "$SHA_PIN_RE" || true)
    [ -z "$_bad" ] || detail="$detail unpinned third-party action(s): $(printf '%s' "$_bad" | tr '\n' '|');"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_least_priv_and_sha_pins

# ---------------------------------------------------------------------------
# TEST 5 — shipped ADVISORY first (continue-on-error: true) per LLD §7 step 1,
# with a TODO to flip to enforcing after the soak.
# ---------------------------------------------------------------------------
test_advisory_first() {
    name="c1-ships-advisory-continue-on-error"
    require_file_or_bail "$name" "$LOCKFILE_YML"
    detail=""
    grep -Eq 'continue-on-error:[[:space:]]*true' "$LOCKFILE_YML" \
        || detail="$detail no continue-on-error: true (must ship advisory first);"
    grep -Eqi 'TODO|soak|flip|enforc' "$LOCKFILE_YML" \
        || detail="$detail no TODO/soak comment to flip advisory->enforcing;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_advisory_first

# ---------------------------------------------------------------------------
# TEST 6 — the setup-pinned-uv COMPOSITE ACTION exists and reads the pin from
# the base ref's CONTENT (M3), not from the PR tree.
# Asserts: composite action; explicit `git fetch --depth=1 origin main` pinned
# to the LITERAL `main` (never github.base_ref); `git show FETCH_HEAD:scripts/
# uv-version.sh`; semver validation `^[0-9]+\.[0-9]+\.[0-9]+$`; a hard failure
# (exit 1) on mismatch (NOT a silent default-to-latest); and a SHA-pinned
# astral-sh/setup-uv that receives the validated version.
# ---------------------------------------------------------------------------
test_setup_pinned_uv_action() {
    name="setup-pinned-uv-reads-base-pin-and-validates-semver"
    require_file_or_bail "$name" "$ACTION_YML"
    detail=""
    # It is a composite action.
    grep -Eq 'using:[[:space:]]*.?composite' "$ACTION_YML" \
        || detail="$detail not a composite action (using: composite);"
    # M3: explicit shallow fetch of the base ref, pinned to the LITERAL main.
    grep -Eq 'git fetch[^\n]*--depth=?[[:space:]]*1[^\n]*origin[[:space:]]+main' "$ACTION_YML" \
        || detail="$detail no 'git fetch --depth=1 origin main' (M3 base-ref fetch);"
    # Must pin to literal main, never the attacker-controllable github.base_ref.
    noncomment "$ACTION_YML" | grep -Eq 'github\.base_ref|GITHUB_BASE_REF' \
        && detail="$detail fetches github.base_ref (must pin to literal 'main', M3/§9);"
    # Reads the pin from FETCH_HEAD content (git show FETCH_HEAD:scripts/uv-version.sh).
    grep -Eq 'git show[[:space:]]+FETCH_HEAD:scripts/uv-version.sh' "$ACTION_YML" \
        || detail="$detail does not 'git show FETCH_HEAD:scripts/uv-version.sh';"
    # Validates the exact-semver regex.
    grep -Eq '\^\[0-9\]\+\\?\.\[0-9\]\+\\?\.\[0-9\]\+\$|\[0-9\]\{1,\}\.\[0-9\]' "$ACTION_YML" \
        || detail="$detail no exact-semver validation (^[0-9]+\\.[0-9]+\\.[0-9]+\$);"
    # FAILS the step on mismatch (no silent default-to-latest): an `exit 1` must
    # be present in the validation path.
    grep -Eq 'exit[[:space:]]+1' "$ACTION_YML" \
        || detail="$detail no 'exit 1' on a semver mismatch (must fail, not default-to-latest);"
    # Uses a SHA-pinned astral-sh/setup-uv.
    grep -Eq 'astral-sh/setup-uv@[0-9a-f]{40}' "$ACTION_YML" \
        || detail="$detail astral-sh/setup-uv not SHA-pinned;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_setup_pinned_uv_action

# ---------------------------------------------------------------------------
# TEST 7 — the composite action's setup-uv is SHA-pinned with a `# vN` comment
# (full pinning convention), and the action does NOT default to "latest".
# ---------------------------------------------------------------------------
test_action_no_latest_fallback() {
    name="setup-pinned-uv-no-latest-fallback-and-vN-comment"
    require_file_or_bail "$name" "$ACTION_YML"
    detail=""
    grep -Eq 'astral-sh/setup-uv@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]' "$ACTION_YML" \
        || detail="$detail astral-sh/setup-uv missing the '# vN' pin comment;"
    # Must not pass version: latest / version: stable to setup-uv (that would
    # defeat the single-source pin).
    grep -Eqi 'version:[[:space:]]*.?(latest|stable)' "$ACTION_YML" \
        && detail="$detail passes 'latest'/'stable' to setup-uv (defeats the pin);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_action_no_latest_fallback

# ---------------------------------------------------------------------------
# Tally + non-zero exit on any failure.
# ---------------------------------------------------------------------------
finish
