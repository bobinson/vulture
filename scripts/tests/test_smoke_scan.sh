#!/usr/bin/env sh
#
# RED-phase test for pending item #3: the release smoke test must run a REAL
# scan, not just install + /health.
#
# These are STATIC assertions over scripts/smoke-install.sh source. The smoke
# test today only installs the tarball and pokes /health; it never proves agent
# EXECUTION. To close item #3, smoke-install.sh must additionally:
#   - invoke `vulture scan` (the installed binary) against a path or git repo, and
#   - assert the scan RESULT is meaningful (findings present OR a completed
#     status) — i.e. an agent actually ran, not merely that the service starts.
#
# Against the pristine tree neither behaviour exists, so every case below FAILs
# (expected RED). This test ONLY asserts the desired behaviour; it does not
# implement the fix.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counter helpers, a final "N passed, M failed" line, exit 1 if
# any case FAILed. No bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

# ---------------------------------------------------------------------------
# Locate the smoke script under test.
# ---------------------------------------------------------------------------
REPO_ROOT=$(repo_root "$0")
SMOKE_SH="$REPO_ROOT/scripts/smoke-install.sh"

require_file_or_bail "smoke-install.sh-present" "$SMOKE_SH"

# ---------------------------------------------------------------------------
# Shared regexes (hoisted so the conjunction test reuses the exact patterns).
#
#   SCAN_INVOKE — the installed binary actually RUN: a `vulture` / `$BIN`
#                 token immediately before `scan`, so a bare word `scan` in a
#                 comment cannot satisfy it.
#   SCAN_TARGET — `scan` followed by a non-flag argument (a path/repo target),
#                 i.e. not `scan --help`.
#   SCAN_RESULT — a real check (grep/test/case/if/-q) keyed on a result token,
#                 not incidental comment prose.
# shellcheck disable=SC2016  # literal $BIN is matched as text in a grep PATTERN, not expanded
SCAN_INVOKE='(vulture|"?\$\{?BIN\}?"?)[[:space:]]+scan'
SCAN_TARGET='scan[[:space:]]+[^-[:space:]]'
SCAN_RESULT='(grep|case|\[ |\bif\b|-q).*(findings?|completed|"status"|severity|score)'

# ---------------------------------------------------------------------------
# TEST 1 — the smoke script invokes a real `vulture scan`.
# It must run the installed binary's `scan` subcommand (the `vulture`/`$BIN`
# token immediately precedes `scan`), proving agent execution rather than only
# that the service starts.
# ---------------------------------------------------------------------------
assert_file_matches \
    "smoke-runs-vulture-scan" \
    "$SMOKE_SH" \
    "$SCAN_INVOKE" \
    "smoke-install.sh never RUNS the installed binary's 'scan'; it only installs + checks /health (item #3 not addressed)"

# ---------------------------------------------------------------------------
# TEST 2 — the scan is pointed at a concrete target (not a flag).
# A scan with only flags cannot prove an agent ran over real code; require a
# `scan` immediately followed by a non-flag argument.
# ---------------------------------------------------------------------------
assert_file_matches \
    "smoke-scan-has-target" \
    "$SMOKE_SH" \
    "$SCAN_TARGET" \
    "the 'vulture scan' invocation has no path/repo target to audit (scan not followed by a non-flag arg)"

# ---------------------------------------------------------------------------
# TEST 3 — the scan RESULT is asserted: findings present OR a completed status.
# Proving EXECUTION means inspecting the scan output, not just exit-on-start.
# The assertion must be a real check — a grep/test/case/if against the scan's
# JSON/text output keyed on a result token — not incidental comment prose.
# ---------------------------------------------------------------------------
assert_file_matches \
    "smoke-asserts-scan-result" \
    "$SMOKE_SH" \
    "$SCAN_RESULT" \
    "smoke-install.sh does not assert the scan produced findings or a completed status (no proof an agent executed)"

# ---------------------------------------------------------------------------
# TEST 4 — guard: the smoke script must do MORE than install + /health.
# Today its only runtime checks are version/doctor/uninstall; a real scan
# assertion is the missing piece. Passes only when BOTH a real scan invocation
# AND a result assertion exist (reusing the exact hoisted patterns above).
# ---------------------------------------------------------------------------
test_more_than_health() {
    name="smoke-beyond-install-and-health"
    if grep -Eq "$SCAN_INVOKE" "$SMOKE_SH" \
        && grep -Eq "$SCAN_RESULT" "$SMOKE_SH"; then
        pass "$name"
    else
        fail "$name" "smoke proves only install + service-up; it must run a scan AND assert its result to prove agent execution"
    fi
}
test_more_than_health

# ---------------------------------------------------------------------------
finish
