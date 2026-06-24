#!/usr/bin/env sh
#
# RED-phase tests for pending item #4 — a `scripts/vulture.sh release` preflight.
#
# These tests are derived ONLY from the desired behaviour, not from any
# implementation. They assert that `vulture.sh` grows a `release` subcommand
# that runs the pre-tag gates and FAILS LOUDLY (non-zero) when any gate fails,
# while `release --help` (a dry/listing path) enumerates the gates without
# running them.
#
# Pre-tag gates the preflight MUST run:
#   - lockfile freshness        (scripts/check-lockfile.sh)
#   - fallback-tag validity     (scripts/check-fallback-tag.sh)
#   - shellcheck of install.sh + scripts
#   - the installer branch tests (scripts/tests/test_install_sh.sh)
#   - a clean-git-tree check
#
# Today there is no `release` subcommand (the dispatch falls through to the
# "unknown command" arm), so every behavioural case here FAILS (expected RED).
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() helpers that increment counters, a final "N passed, M failed"
# line, and exit 1 if any case FAILed. Functions are tiny (cyclomatic < 5), DRY,
# no bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

# ---------------------------------------------------------------------------
# Locate the script under test + its gate scripts.
# ---------------------------------------------------------------------------
REPO_ROOT=$(repo_root "$0")
VULTURE_SH="$REPO_ROOT/scripts/vulture.sh"

make_sandbox

require_file_or_bail "vulture.sh-present" "$VULTURE_SH"

# run_release <outfile> <args...> : invoke `vulture.sh release <args>`, capture
# combined output to <outfile> and ECHO the exit code to stdout. DRY helper used
# by every case. Runs from REPO_ROOT so git/gate scripts see the real tree.
OUT="$SANDBOX/out"
run_release() {
    _outfile=$1
    shift
    ( cd "$REPO_ROOT" && sh "$VULTURE_SH" release "$@" ) > "$_outfile" 2>&1
    echo $?
}

# Spawn `release --help` EXACTLY ONCE; TEST 1/2/3 all read this captured run
# (output in $HELP_OUT, exit code in $HELP_RC) rather than re-spawning it.
HELP_OUT="$OUT.help"
HELP_RC=$(run_release "$HELP_OUT" --help)

# ---------------------------------------------------------------------------
# TEST 1 — `release` is a RECOGNISED subcommand.
# The dispatch must NOT route it to the "unknown command" arm. Today it does,
# so this FAILs (RED).
# ---------------------------------------------------------------------------
test_release_recognised() {
    name="release-is-a-recognised-subcommand"
    if grep -Eqi "unknown command" "$HELP_OUT"; then
        fail "$name" "release routed to the unknown-command arm (subcommand not implemented; rc=$HELP_RC)"
    else
        pass "$name"
    fi
}
test_release_recognised

# ---------------------------------------------------------------------------
# TEST 2 — `release --help` LISTS every gate (dry/listing path, exit 0).
# The help/dry path must enumerate all five gates by name and must NOT run them
# (so it is safe + fast). We assert each gate keyword appears in the help text.
# ---------------------------------------------------------------------------
test_release_help_lists_gates() {
    name="release-help-lists-all-gates"
    detail=""
    [ "$HELP_RC" -eq 0 ] || detail="$detail --help exited non-zero (rc=$HELP_RC);"
    grep -Eqi "check-lockfile|lockfile" "$HELP_OUT" || detail="$detail no lockfile-freshness gate listed;"
    grep -Eqi "check-fallback-tag|fallback.?tag" "$HELP_OUT" || detail="$detail no fallback-tag gate listed;"
    grep -Eqi "shellcheck" "$HELP_OUT" || detail="$detail no shellcheck gate listed;"
    grep -Eqi "test_install_sh|installer.+test|branch test" "$HELP_OUT" || detail="$detail no installer-branch-tests gate listed;"
    grep -Eqi "clean.?git|clean.?tree|working tree|uncommitted" "$HELP_OUT" || detail="$detail no clean-git-tree gate listed;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_release_help_lists_gates

# ---------------------------------------------------------------------------
# TEST 3 — the preflight actually WIRES the gates (DELEGATION-TOLERANT).
# A real run must invoke the named gate scripts. The `release)` arm may either
# reference the gates inline OR delegate (exec/source) to a helper script; we
# follow any delegated *.sh under scripts/ and assert the gate references across
# the arm body + every helper it delegates to. Today there is no `release)` arm
# at all, so the slice is empty and nothing is referenced -> RED.
# ---------------------------------------------------------------------------
# slice_release_arm — print the `release)` case-arm body, anchored to a line
# that STARTS (after optional indent) with `release)`, up to its `;;`.
slice_release_arm() {
    sed -n '/^[[:space:]]*release)/,/;;/p' "$VULTURE_SH"
}

# delegated_helpers <arm-body> — print absolute paths of any *.sh the arm
# delegates to via exec/./source, resolved under scripts/ (so a helper's own
# body can be searched for the gate references).
delegated_helpers() {
    printf '%s\n' "$1" \
        | grep -E '(exec|\.|source)[[:space:]]' \
        | grep -oE '[A-Za-z0-9_./-]+\.sh' \
        | while IFS= read -r _rel; do
            _base=$(basename "$_rel")
            if [ -f "$REPO_ROOT/scripts/$_base" ]; then
                printf '%s\n' "$REPO_ROOT/scripts/$_base"
            elif [ -f "$REPO_ROOT/$_rel" ]; then
                printf '%s\n' "$REPO_ROOT/$_rel"
            fi
        done
}

test_release_wires_gate_scripts() {
    name="release-wires-the-gate-scripts"
    arm=$(slice_release_arm)
    # Search corpus = the arm body PLUS every delegated helper's source.
    corpus=$arm
    for _h in $(delegated_helpers "$arm"); do
        corpus="$corpus
$(cat "$_h" 2>/dev/null)"
    done
    detail=""
    printf '%s' "$corpus" | grep -q "check-lockfile.sh" || detail="$detail check-lockfile.sh not referenced;"
    printf '%s' "$corpus" | grep -q "check-fallback-tag.sh" || detail="$detail check-fallback-tag.sh not referenced;"
    printf '%s' "$corpus" | grep -q "test_install_sh.sh" || detail="$detail test_install_sh.sh not referenced;"
    printf '%s' "$corpus" | grep -Eqi "shellcheck" || detail="$detail shellcheck not invoked;"
    printf '%s' "$corpus" | grep -Eqi "git (status|diff)" || detail="$detail clean-git-tree check not invoked;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_release_wires_gate_scripts

# ---------------------------------------------------------------------------
# TEST 4 — FAILS LOUDLY, and for the RIGHT reason: a DIRTY git tree must make the
# preflight exit non-zero BECAUSE the clean-git-tree gate tripped — not because
# some earlier gate (e.g. lockfile) happened to fail first. We create an
# untracked junk file in REPO_ROOT so the clean-git-tree gate trips, run the
# preflight (its OWN invocation — not the cached --help run), then remove it.
#
# This verifies the gate ORDERING: clean-tree must run FIRST (fail-fast), so the
# loud failure names the clean-tree gate. We assert (a) non-zero exit, (b) not
# the unknown-command mode, and (c) the failure message is the clean-tree gate's
# (its die() reports the dirty/uncommitted working tree).
# ---------------------------------------------------------------------------
test_release_fails_on_dirty_tree() {
    name="release-fails-loudly-on-dirty-tree-clean-tree-gate"
    junk="$REPO_ROOT/.vulture-release-preflight-dirty-probe"
    : > "$junk"
    rc=$(run_release "$OUT.dirty")
    rm -f "$junk"
    # The clean-tree gate's FAILURE signature: its die() names the dirty working
    # tree OR the run_gate label "clean git tree" is the one reported FAILED.
    # These strings appear ONLY when the clean-tree gate actually trips — NOT in
    # the gate-listing banner (which says "no uncommitted changes (git status)")
    # and NOT when an earlier gate fails first (e.g. "FAILED — lockfile
    # freshness"). So matching this proves clean-tree ran FIRST and tripped,
    # which is exactly the ordering #8 requires.
    _cleantree_re='(working tree is dirty|unstaged changes present|FAILED.*clean git tree)'
    if grep -Eqi "unknown command" "$OUT.dirty"; then
        fail "$name" "release unrecognised (failure was unknown-command, not a tripped gate)"
    elif [ "$rc" -eq 0 ]; then
        fail "$name" "preflight returned 0 on a dirty git tree; expected loud non-zero failure"
    elif ! grep -Eqi "$_cleantree_re" "$OUT.dirty"; then
        fail "$name" "preflight failed on a dirty tree but NOT via the clean-tree gate (clean-tree must run first; output: $(tr '\n' ' ' < "$OUT.dirty"))"
    else
        pass "$name"
    fi
}
test_release_fails_on_dirty_tree

# ===========================================================================
# 0056 C4 — the SIXTH gate "security" must be wired into the preflight, and the
# gate must appear in ALL THREE hand-synced lists that the LLD §13 (audit
# "3 places") requires to agree:
#   (1) the file-header comment's enumerated gate list,
#   (2) the print_gates heredoc (the --help contract),
#   (3) the run_gate dispatch (the actual wiring).
# These are STATIC assertions over scripts/release-preflight.sh (the delegate
# `vulture.sh release` exec's). Against the 5-gate tree they FAIL (expected RED):
# there is no security gate in any of the three lists yet.
# ---------------------------------------------------------------------------
PREFLIGHT_SH="$REPO_ROOT/scripts/release-preflight.sh"

# header_block — the leading comment block (lines before the first non-comment,
# non-blank shell statement), where the gate list is enumerated.
header_block() {
    sed -n '1,/^[^#[:space:]]/p' "$PREFLIGHT_SH"
}

# print_gates_block — the body of the print_gates heredoc (between the opening
# `<<'EOF'` and its closing `EOF`), i.e. the --help contract text.
print_gates_block() {
    sed -n "/print_gates()/,/^EOF/p" "$PREFLIGHT_SH"
}

# rungate_block — the run_gate DISPATCH lines only (the actual wiring): lines
# that, after optional leading whitespace, invoke `run_gate <label> ...`. This
# excludes the function definition (`run_gate() {`) and prose comments that
# merely mention run_gate, so the parity count reflects real gate invocations.
rungate_block() {
    grep -E '^[[:space:]]*run_gate[[:space:]]+"' "$PREFLIGHT_SH"
}

# ---------------------------------------------------------------------------
# TEST 5 — the security gate is present in the FILE-HEADER comment list.
# ---------------------------------------------------------------------------
test_security_in_header() {
    name="security-gate-in-file-header-comment-list"
    require_file_or_bail "$name" "$PREFLIGHT_SH"
    if header_block | grep -Eqi 'security'; then
        pass "$name"
    else
        fail "$name" "the file-header gate list does not enumerate a 'security' gate (3-list parity)"
    fi
}
test_security_in_header

# ---------------------------------------------------------------------------
# TEST 6 — the security gate is present in the print_gates heredoc (--help).
# It must name both the gate ("security") and its helper (security-preflight.sh).
# ---------------------------------------------------------------------------
test_security_in_print_gates() {
    name="security-gate-in-print_gates-help-heredoc"
    require_file_or_bail "$name" "$PREFLIGHT_SH"
    detail=""
    print_gates_block | grep -Eqi 'security' \
        || detail="$detail print_gates heredoc omits the 'security' gate;"
    print_gates_block | grep -q 'security-preflight.sh' \
        || detail="$detail print_gates heredoc omits scripts/security-preflight.sh;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_security_in_print_gates

# ---------------------------------------------------------------------------
# TEST 7 — the security gate is actually WIRED via run_gate "security" pointing
# at security-preflight.sh (the 6th gate).
# ---------------------------------------------------------------------------
test_security_run_gate_wired() {
    name="security-gate-wired-via-run_gate"
    require_file_or_bail "$name" "$PREFLIGHT_SH"
    detail=""
    rungate_block | grep -Eqi 'run_gate[[:space:]]+.?security' \
        || detail="$detail no run_gate \"security\" dispatch;"
    rungate_block | grep -q 'security-preflight.sh' \
        || detail="$detail run_gate \"security\" does not invoke security-preflight.sh;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_security_run_gate_wired

# ---------------------------------------------------------------------------
# TEST 8 — 3-LIST PARITY: the count of gates declared in the header, the
# print_gates heredoc, and the run_gate dispatch must AGREE (LLD §13: all three
# hand-synced lists must stay in lockstep). We count the numbered gate lines in
# the header + heredoc (`N. `) and the run_gate calls, and require all three to
# be equal AND >= 6 (the security gate brought it to six).
# ---------------------------------------------------------------------------
test_three_list_parity() {
    name="gate-lists-agree-in-all-three-places"
    require_file_or_bail "$name" "$PREFLIGHT_SH"
    _h=$(header_block      | grep -Ec '^#[[:space:]]*[0-9]+\.[[:space:]]')
    _p=$(print_gates_block | grep -Ec '^[[:space:]]*[0-9]+\.[[:space:]]')
    _r=$(rungate_block     | grep -Ec 'run_gate')
    detail=""
    [ "$_h" -ge 6 ] || detail="$detail header lists $_h gates (want >=6);"
    [ "$_p" -ge 6 ] || detail="$detail print_gates lists $_p gates (want >=6);"
    [ "$_r" -ge 6 ] || detail="$detail run_gate dispatches $_r gates (want >=6);"
    { [ "$_h" -eq "$_p" ] && [ "$_p" -eq "$_r" ]; } \
        || detail="$detail counts disagree (header=$_h print_gates=$_p run_gate=$_r);"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_three_list_parity

# ---------------------------------------------------------------------------
# Tally.
# ---------------------------------------------------------------------------
finish
