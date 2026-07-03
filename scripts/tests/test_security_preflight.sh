#!/usr/bin/env sh
#
# RED-phase BEHAVIORAL tests for 0056 C4 — scripts/security-preflight.sh.
#
# C4 is the pre-tag Python-deps security gate. These tests drive the REAL
# script with a hermetic, deterministic environment: they inject fake
# `pip-audit` / `gh` binaries on PATH (and remove them) so every branch is
# exercised regardless of what is installed on the host — the suite does NOT
# depend on a real pip-audit/gh being present. (If the host's pip-audit/gh
# leaked into the test it would be non-deterministic; the PATH override below
# is what makes this behavioral test reproducible in CI and on a laptop.)
#
# Asserted contract (LLD 0056 §5 C4; audit M2, M9; §11 chaos catalog):
#   1) pip-audit is RUN over agents/requirements-frozen.txt; a HIGH/CRITICAL
#      finding with NO matching waiver FAILS the gate (non-zero).
#   2) A waiver in .pip-audit-ignore whose ID is GHSA-* (NOT a CVE) makes the
#      same finding PASS — the parser MUST accept ^(CVE|GHSA|PYSEC|OSV)- (M9),
#      not just ^CVE-.
#   3) Clean pip-audit (no findings) PASSES.
#   4) `gh` ABSENT (or no token) ⇒ a LOUD warning AND the gate refuses to
#      proceed unless VULTURE_ACK_NO_ALERTS=true is set (M2: the default
#      GITHUB_TOKEN cannot read /dependabot/alerts, so an unacknowledged
#      missing-alert-feed must not be silently ignored). With the ack set the
#      gate proceeds (degrades to pip-audit-only).
#   5) pip-audit ITSELF absent ⇒ the gate FAILS (we refuse to tag with no local
#      dependency audit available — §11: "pip-audit absent locally → gate
#      fails"). NOT a skip.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final "N passed, M failed" line, exit 1 on any FAIL.
# Tiny functions (cyclomatic < 5), DRY, no bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
SEC_SH="$REPO_ROOT/scripts/security-preflight.sh"

make_sandbox
require_file_or_bail "security-preflight.sh-present" "$SEC_SH"

# ---------------------------------------------------------------------------
# Fixture builders — all hermetic, all under $SANDBOX.
# ---------------------------------------------------------------------------
BIN="$SANDBOX/bin"          # fake-tool dir we prepend to PATH per case
mkdir -p "$BIN"

# requirements file the gate audits (its existence is incidental — the fake
# pip-audit ignores its content; we just point the gate at a real path).
REQ="$SANDBOX/requirements-frozen.txt"
printf 'requests==2.32.0\n' > "$REQ"

# write_pip_audit <mode> — install a fake `pip-audit` on $BIN.
#   mode=high  : emits a HIGH finding for GHSA-xxxx-yyyy-zzzz and exits non-zero
#                (pip-audit's real behavior under --strict on a finding).
#   mode=clean : prints "No known vulnerabilities found" and exits 0.
# It honors --ignore-vuln <ID>: if the GHSA id is passed as ignored, it drops
# the finding and exits 0 (mirrors pip-audit's real waiver semantics), which is
# how we prove the gate FORWARDS waivers to pip-audit.
write_pip_audit() {
    _mode=$1
    cat > "$BIN/pip-audit" <<EOF
#!/bin/sh
# Fake pip-audit for the C4 behavioral test (mode=$_mode).
ignored=""
for a in "\$@"; do
    case "\$prev" in --ignore-vuln) ignored="\$ignored \$a";; esac
    case "\$a" in --ignore-vuln=*) ignored="\$ignored \${a#--ignore-vuln=}";; esac
    prev="\$a"
done
if [ "$_mode" = clean ]; then
    echo "No known vulnerabilities found"
    exit 0
fi
# mode=high: one HIGH finding for this advisory id.
ADV="GHSA-xxxx-yyyy-zzzz"
case " \$ignored " in
    *" \$ADV "*) echo "No known vulnerabilities found (1 ignored)"; exit 0;;
esac
echo "Found 1 known vulnerability in 1 package"
echo "Name     Version ID                   Fix Versions Severity"
echo "requests 2.32.0  \$ADV                 2.32.1       HIGH"
exit 1
EOF
    chmod +x "$BIN/pip-audit"
}

# write_gh — install a fake `gh` that succeeds with an empty alert list (so the
# alert path, when present, does not itself fail the gate).
write_gh() {
    cat > "$BIN/gh" <<'EOF'
#!/bin/sh
# Fake gh: a successful, empty Dependabot-alerts response.
echo "[]"
exit 0
EOF
    chmod +x "$BIN/gh"
}

# write_ignore <line...> — write .pip-audit-ignore into the sandbox repo dir.
# The gate is told where to read it via env (VULTURE_PIP_AUDIT_IGNORE) so the
# test never touches the real repo's allowlist.
IGNORE="$SANDBOX/.pip-audit-ignore"
write_ignore() {
    : > "$IGNORE"
    for _l in "$@"; do printf '%s\n' "$_l" >> "$IGNORE"; done
}

# run_gate_case <outfile> [ack] — invoke security-preflight.sh with $BIN
# prepended to PATH, pointing it at the sandbox requirements + ignore file.
# Echoes the exit code; combined output goes to <outfile>. The gate is told the
# requirements path + ignore path via env so the suite is hermetic.
#   ack="ack" -> export VULTURE_ACK_NO_ALERTS=true for this run; anything else
#                (or omitted) -> the variable is UNSET (the no-ack case).
# Each var is set as a real assignment in the subshell (not via an `env` prefix:
# this host ships an `env` shim that swallows its command, and a `VAR=val` taken
# from "$@" expansion is not honored as an assignment by POSIX sh anyway).
run_gate_case() {
    _out=$1
    _ack=${2:-}
    (
        PATH="$BIN:$PATH"
        VULTURE_REQUIREMENTS="$REQ"
        VULTURE_PIP_AUDIT_IGNORE="$IGNORE"
        export PATH VULTURE_REQUIREMENTS VULTURE_PIP_AUDIT_IGNORE
        if [ "$_ack" = "ack" ]; then
            VULTURE_ACK_NO_ALERTS=true
            export VULTURE_ACK_NO_ALERTS
        else
            unset VULTURE_ACK_NO_ALERTS 2>/dev/null || true
        fi
        sh "$SEC_SH"
    ) > "$_out" 2>&1
    echo $?
}

# ---------------------------------------------------------------------------
# TEST 1 — HIGH finding, NO waiver ⇒ gate FAILS (non-zero).
# (Ack the missing-alert feed so this case isolates the pip-audit verdict, not
# the alert-token gate which TEST 4 covers.)
# ---------------------------------------------------------------------------
test_high_no_waiver_fails() {
    name="high-finding-without-waiver-fails-the-gate"
    write_pip_audit high
    write_gh                 # alerts available + empty, so they don't interfere
    write_ignore             # empty allowlist
    rc=$(run_gate_case "$SANDBOX/t1" ack)
    if [ "$rc" -ne 0 ]; then
        pass "$name"
    else
        fail "$name" "gate returned 0 on an un-waived HIGH advisory (want non-zero); out: $(tr '\n' ' ' < "$SANDBOX/t1")"
    fi
}
test_high_no_waiver_fails

# ---------------------------------------------------------------------------
# TEST 2 — HIGH finding WAIVED by a GHSA-* line ⇒ gate PASSES (M9).
# Proves the parser accepts GHSA (not only CVE) and forwards it to pip-audit.
# ---------------------------------------------------------------------------
test_ghsa_waiver_passes() {
    name="ghsa-waiver-passes-the-gate-M9"
    write_pip_audit high
    write_gh
    write_ignore "GHSA-xxxx-yyyy-zzzz: test waiver (expires 2099-01-01)"
    rc=$(run_gate_case "$SANDBOX/t2" ack)
    if [ "$rc" -eq 0 ]; then
        pass "$name"
    else
        fail "$name" "gate failed despite a GHSA waiver (M9: parser must accept ^(CVE|GHSA|PYSEC|OSV)-); out: $(tr '\n' ' ' < "$SANDBOX/t2")"
    fi
}
test_ghsa_waiver_passes

# ---------------------------------------------------------------------------
# TEST 3 — clean pip-audit (no findings) ⇒ gate PASSES.
# ---------------------------------------------------------------------------
test_clean_passes() {
    name="clean-pip-audit-passes-the-gate"
    write_pip_audit clean
    write_gh
    write_ignore
    rc=$(run_gate_case "$SANDBOX/t3" ack)
    if [ "$rc" -eq 0 ]; then
        pass "$name"
    else
        fail "$name" "gate failed on a clean pip-audit; out: $(tr '\n' ' ' < "$SANDBOX/t3")"
    fi
}
test_clean_passes

# ---------------------------------------------------------------------------
# TEST 4 — gh ABSENT ⇒ LOUD warning + the gate refuses without
# VULTURE_ACK_NO_ALERTS=true; WITH the ack it proceeds (M2).
# We remove the fake gh from $BIN so `gh` is genuinely absent on the test PATH.
# pip-audit is clean so the ONLY thing that can fail the gate is the missing
# alert feed — isolating the M2 ack behavior.
# ---------------------------------------------------------------------------
test_gh_absent_requires_ack() {
    name="gh-absent-warns-and-requires-VULTURE_ACK_NO_ALERTS"
    write_pip_audit clean
    rm -f "$BIN/gh"          # gh genuinely absent
    write_ignore
    # (a) WITHOUT the ack: must warn LOUDLY and FAIL.
    rc_noack=$(run_gate_case "$SANDBOX/t4a")
    # (b) WITH the ack: must proceed (pass, since pip-audit is clean).
    rc_ack=$(run_gate_case "$SANDBOX/t4b" ack)
    detail=""
    grep -Eqi 'warn|warning|alert|dependabot' "$SANDBOX/t4a" \
        || detail="$detail no loud warning about the missing alert feed;"
    [ "$rc_noack" -ne 0 ] \
        || detail="$detail proceeded (rc=0) with gh absent and no ack (M2: must refuse);"
    [ "$rc_ack" -eq 0 ] \
        || detail="$detail did NOT proceed with VULTURE_ACK_NO_ALERTS=true (rc=$rc_ack); out: $(tr '\n' ' ' < "$SANDBOX/t4b");"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_gh_absent_requires_ack

# ---------------------------------------------------------------------------
# TEST 5 — pip-audit ITSELF absent ⇒ the gate FAILS (NOT a skip).
# We remove the fake pip-audit so it is genuinely absent on the test PATH. The
# ack is set so the alert-feed gate cannot be the cause — the ONLY reason to
# fail is the missing core auditor.
# ---------------------------------------------------------------------------
test_pip_audit_absent_fails() {
    name="pip-audit-absent-fails-the-gate"
    rm -f "$BIN/pip-audit"   # core auditor genuinely absent
    write_gh
    write_ignore
    rc=$(run_gate_case "$SANDBOX/t5" ack)
    detail=""
    [ "$rc" -ne 0 ] \
        || detail="$detail gate returned 0 with pip-audit absent (must FAIL — refuse to tag with no local audit);"
    grep -Eqi 'pip-audit' "$SANDBOX/t5" \
        || detail="$detail failure did not mention pip-audit; out: $(tr '\n' ' ' < "$SANDBOX/t5");"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_pip_audit_absent_fails

# ---------------------------------------------------------------------------
# Tally.
# ---------------------------------------------------------------------------
finish
