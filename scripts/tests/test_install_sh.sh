#!/usr/bin/env sh
#
# RED-phase branch tests for install.sh (feature 0055 hardening).
#
# These tests are derived ONLY from the 0055 implementation plan (the LLD),
# not from any implementation. They exercise the documented behaviours of:
#   - the source-only testability seam (VULTURE_INSTALL_SOURCE_ONLY)
#   - verify_signature       (A1 cosign arg shape; no-sig SHA-only fallback)
#   - install_python_deps    (A2 CLI-only / fail-closed; H1 TLS; H3 extras)
#   - reject_if_system_dir   (A4 / H4 / H5 blacklist)
#   - strip_quarantine       (A3 .filelist cleanup on linux)
#   - commit_install/cleanup (H2 crash-consistent upgrade)
#
# Harness contract: POSIX sh, set -u, mktemp sandbox + EXIT trap, PATH shims
# for cosign/pip, source install.sh ONCE with the seam, then run each
# err-exiting function inside a ( ... ) subshell. Prints PASS/FAIL per case,
# a final count, and exits non-zero if any case FAILed.

set -u

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf 'PASS [%s]\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
INSTALL_SH="$REPO_ROOT/install.sh"

SANDBOX=$(mktemp -d 2>/dev/null || mktemp -d -t vulture-test)
cleanup_sandbox() { rm -rf "$SANDBOX"; }
trap cleanup_sandbox EXIT INT TERM

if [ ! -f "$INSTALL_SH" ]; then
    fail "install.sh-present" "install.sh not found at $INSTALL_SH"
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    exit 1
fi

# ---------------------------------------------------------------------------
# PATH shims. cosign/pip record their argv so we can assert on it.
# ---------------------------------------------------------------------------
SHIMBIN="$SANDBOX/bin"
mkdir -p "$SHIMBIN"

COSIGN_LOG="$SANDBOX/cosign.argv"
PIP_LOG="$SANDBOX/pip.argv"

cat > "$SHIMBIN/cosign" <<EOF
#!/usr/bin/env sh
# Record each positional arg on its own line, plus a full single-line copy.
: > "$COSIGN_LOG.lines"
for a in "\$@"; do printf '%s\n' "\$a" >> "$COSIGN_LOG.lines"; done
printf '%s ' "\$@" > "$COSIGN_LOG"
printf '\n' >> "$COSIGN_LOG"
exit 0
EOF
chmod +x "$SHIMBIN/cosign"

# pip shim records argv; lives at $SANDBOX/python-runtime/bin/pip so a bundled
# runtime layout can be simulated.  A generic 'pip' on PATH also logs.
make_pip() {
    _dest=$1
    mkdir -p "$(dirname "$_dest")"
    cat > "$_dest" <<EOF
#!/usr/bin/env sh
printf '%s ' "\$@" >> "$PIP_LOG"
printf '\n' >> "$PIP_LOG"
exit 0
EOF
    chmod +x "$_dest"
}
make_pip "$SHIMBIN/pip"
make_pip "$SHIMBIN/pip3"

PATH="$SHIMBIN:$PATH"
export PATH

# ---------------------------------------------------------------------------
# TEST 1 — testability seam.
# Sourcing install.sh with VULTURE_INSTALL_SOURCE_ONLY=1 must NOT run main()
# (no installer side-effects / output).  Against the pristine tree the seam
# does not exist so main() runs on source -> this test FAILS (expected RED).
#
# To keep the harness alive while pristine main() runs (it reaches the
# network / platform detection), we stub curl + cosign on PATH and source
# inside a subshell, capturing all output.
# ---------------------------------------------------------------------------
cat > "$SHIMBIN/curl" <<'EOF'
#!/usr/bin/env sh
# Pristine main() may call curl; emit nothing and succeed so we don't hang.
exit 0
EOF
chmod +x "$SHIMBIN/curl"

seam_out=$(
    VULTURE_INSTALL_SOURCE_ONLY=1
    export VULTURE_INSTALL_SOURCE_ONLY
    # shellcheck disable=SC1090
    . "$INSTALL_SH" 2>&1
    # If we reach here without main() having exited the subshell, print a marker.
    printf '__SOURCED_OK__\n'
)

# Heuristic: pristine main() prints platform detection / install progress.
# A working seam suppresses ALL of that and leaves the __SOURCED_OK__ marker.
if printf '%s' "$seam_out" | grep -Eqi 'detect|platform|installing|downloading|verify|tarball'; then
    fail "seam-suppresses-main" "main() ran on source (installer output present); VULTURE_INSTALL_SOURCE_ONLY not honored"
elif printf '%s' "$seam_out" | grep -q '__SOURCED_OK__'; then
    pass "seam-suppresses-main"
else
    fail "seam-suppresses-main" "sourcing did not return control (main likely ran and exited subshell). output: $(printf '%s' "$seam_out" | tr '\n' '|' | cut -c1-160)"
fi

# ---------------------------------------------------------------------------
# Per-test sourcing model.
#
# install.sh runs main() at end-of-file unless the VULTURE_INSTALL_SOURCE_ONLY
# seam suppresses it.  main() typically calls exit, which would terminate this
# whole harness if we dot-sourced in-process.  So every function-level test
# runs in its OWN subshell that:
#   1) exports the seam,
#   2) dot-sources install.sh (with the seam working, main() does NOT run and
#      control returns; without it, main() runs and exit()s the subshell here),
#   3) calls the target function,
#   4) writes a DONE sentinel + any captured result.
# If step 2 ran main() and exited, steps 3-4 never happen and the sentinel is
# absent -> the test reports the function as unreachable/undefined (RED).
#
# run_in_install <result-file> <shell-body>  — body runs after the source.
# ---------------------------------------------------------------------------
set +e
set +u

run_in_install() {
    _body=$1
    (
        VULTURE_INSTALL_SOURCE_ONLY=1
        export VULTURE_INSTALL_SOURCE_ONLY
        # shellcheck disable=SC1090
        . "$INSTALL_SH" >/dev/null 2>&1
        # Reached only if the seam suppressed main(). Run the test body.
        eval "$_body"
    )
}

# Probe once whether the seam is honored at all (functions reachable).
SEAM_OK=0
if run_in_install 'type verify_signature >/dev/null 2>&1 && echo SEAM > "$SANDBOX/seam.probe"' >/dev/null 2>&1; then :; fi
[ -f "$SANDBOX/seam.probe" ] && SEAM_OK=1

# ---------------------------------------------------------------------------
# TEST 2 — A1 cosign arg shape.
# verify_signature, when a signature + certificate are present, must call
# cosign verify-blob with EXACTLY ONE positional (the SHASUM blob), the cert
# passed via --certificate (a flag, not a bare positional .pem), and the sig
# via --signature.
# ---------------------------------------------------------------------------
test_cosign_argshape() {
    name="A1-cosign-arg-shape"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "verify_signature unreachable: seam absent (main ran on source)"
        return
    fi
    work="$SANDBOX/a1"
    mkdir -p "$work"
    SHASUM_FILE="$work/SHA256SUMS"
    SIG_FILE="$work/SHA256SUMS.sig"
    printf 'deadbeef  vulture\n' > "$SHASUM_FILE"
    printf 'sig\n' > "$SIG_FILE"
    printf 'cert\n' > "$work/SHA256SUMS.pem"
    : > "$COSIGN_LOG.lines"
    : > "$COSIGN_LOG"
    run_in_install '
        SHASUM_FILE="'"$SHASUM_FILE"'"
        SIG_FILE="'"$SIG_FILE"'"
        REPO_OWNER="freedomledger"
        REPO_NAME="vulture"
        export SHASUM_FILE SIG_FILE REPO_OWNER REPO_NAME
        verify_signature
    ' >/dev/null 2>&1

    if [ ! -s "$COSIGN_LOG" ]; then
        fail "$name" "cosign was not invoked (verify_signature did not call cosign verify-blob)"
        return
    fi
    # Count positionals: argv lines that are NOT a flag and not the value
    # immediately following a value-taking flag.
    npos=0
    extra_pem=0
    has_cert_flag=0
    has_sig_flag=0
    saw_verify_blob=0
    skip_next=0
    first=1
    while IFS= read -r tok; do
        if [ "$first" = 1 ]; then first=0; fi
        case "$tok" in
            verify-blob) saw_verify_blob=1; continue ;;
        esac
        if [ "$skip_next" = 1 ]; then skip_next=0; continue; fi
        case "$tok" in
            --certificate) has_cert_flag=1; skip_next=1; continue ;;
            --signature) has_sig_flag=1; skip_next=1; continue ;;
            --certificate-identity-regexp|--certificate-oidc-issuer|--rekor-url|--certificate-identity) skip_next=1; continue ;;
            --*) continue ;;
        esac
        # a bare positional
        npos=$((npos + 1))
        case "$tok" in
            *.pem) extra_pem=1 ;;
        esac
    done < "$COSIGN_LOG.lines"

    detail=""
    [ "$saw_verify_blob" = 1 ] || detail="$detail no verify-blob subcommand;"
    [ "$npos" -eq 1 ] || detail="$detail expected 1 positional, got $npos;"
    [ "$extra_pem" = 0 ] || detail="$detail stray .pem passed as a positional;"
    [ "$has_cert_flag" = 1 ] || detail="$detail cert not passed via --certificate;"
    [ "$has_sig_flag" = 1 ] || detail="$detail sig not passed via --signature;"

    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_cosign_argshape

# ---------------------------------------------------------------------------
# TEST 3 — verify_signature no-signature -> SHA-only (cosign NOT called).
# When no .pem/sig is published, verify must warn + fall back to SHA-only and
# must NOT invoke cosign.  (This branch may already pass on pristine code.)
# ---------------------------------------------------------------------------
test_verify_nosig() {
    name="A1-no-sig-sha-only"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "verify_signature unreachable: seam absent (main ran on source)"
        return
    fi
    work="$SANDBOX/nosig"
    mkdir -p "$work"
    SHASUM_FILE="$work/SHA256SUMS"
    printf 'deadbeef  vulture\n' > "$SHASUM_FILE"
    # No .pem, no .sig present.
    : > "$COSIGN_LOG"
    : > "$COSIGN_LOG.lines"
    run_in_install '
        SHASUM_FILE="'"$SHASUM_FILE"'"
        SIG_FILE="'"$work"'/SHA256SUMS.sig"
        REPO_OWNER="freedomledger"
        REPO_NAME="vulture"
        export SHASUM_FILE SIG_FILE REPO_OWNER REPO_NAME
        verify_signature
    ' >/dev/null 2>&1
    rc=$?
    if [ -s "$COSIGN_LOG" ]; then
        fail "$name" "cosign was invoked despite missing certificate (should be SHA-only fallback)"
    elif [ "$rc" -ne 0 ]; then
        fail "$name" "verify_signature returned non-zero ($rc) on no-sig; expected graceful SHA-only return"
    else
        pass "$name"
    fi
}
test_verify_nosig

# ---------------------------------------------------------------------------
# install_python_deps helpers
# ---------------------------------------------------------------------------
# Build a VULTURE_HOME layout.  bundled pip lives at
# $VULTURE_HOME/runtime/python/bin/pip; the frozen manifest at
# $VULTURE_HOME/runtime/agents/requirements-frozen.txt (paths per LLD prose).
setup_home() {
    _h=$1
    rm -rf "$_h"
    mkdir -p "$_h/runtime/python/bin" "$_h/runtime/agents"
    echo "$_h"
}

# ---------------------------------------------------------------------------
# TEST 4 — A2 CLI-only success (no bundled pip) -> return success, no err.
# ---------------------------------------------------------------------------
test_deps_cli_only() {
    name="A2-cli-only-success"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "install_python_deps unreachable: seam absent (main ran on source)"
        return
    fi
    h=$(setup_home "$SANDBOX/h-clionly")
    # No bundled pip created.
    : > "$PIP_LOG"
    out=$(run_in_install '
        VULTURE_HOME="'"$h"'"
        export VULTURE_HOME
        install_python_deps 2>&1
    ')
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$name" "expected success (return 0) when bundled pip absent, got rc=$rc; out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-120)"
    elif printf '%s' "$out" | grep -Eqi 'docker|mode a|mode b|cli|not bundled|agent runtime'; then
        pass "$name"
    else
        fail "$name" "succeeded but no CLI-only/Docker caveat message printed; out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-120)"
    fi
}
test_deps_cli_only

# ---------------------------------------------------------------------------
# TEST 5 — A2 hashless frozen -> fail-closed (err / non-zero exit).
# ---------------------------------------------------------------------------
test_deps_hashless() {
    name="A2-hashless-fail-closed"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "install_python_deps unreachable: seam absent (main ran on source)"
        return
    fi
    h=$(setup_home "$SANDBOX/h-hashless")
    make_pip "$h/runtime/python/bin/pip"
    printf 'requests==2.31.0\nflask==3.0.0\n' > "$h/runtime/agents/requirements-frozen.txt"
    : > "$PIP_LOG"
    run_in_install '
        VULTURE_HOME="'"$h"'"
        export VULTURE_HOME
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "$name" "expected non-zero (fail-closed) on hashless frozen manifest, got rc=0"
    elif [ -s "$PIP_LOG" ]; then
        fail "$name" "pip was invoked on a hashless manifest (should refuse before installing)"
    else
        pass "$name"
    fi
}
test_deps_hashless

# ---------------------------------------------------------------------------
# TEST 6 — H3 hashless-with-extras -> fail-closed.
# A line like 'uvicorn[standard]==0.30.0' (extras) must still be detected as a
# requirement line and, lacking --hash=, must fail closed.
# ---------------------------------------------------------------------------
test_deps_hashless_extras() {
    name="H3-hashless-extras-fail-closed"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "install_python_deps unreachable: seam absent (main ran on source)"
        return
    fi
    h=$(setup_home "$SANDBOX/h-extras")
    make_pip "$h/runtime/python/bin/pip"
    {
        printf '# comment line, not a requirement\n'
        printf 'uvicorn[standard]==0.30.0\n'
        printf 'pydantic[email]>=2.0\n'
    } > "$h/runtime/agents/requirements-frozen.txt"
    : > "$PIP_LOG"
    run_in_install '
        VULTURE_HOME="'"$h"'"
        export VULTURE_HOME
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "$name" "expected fail-closed on hashless manifest with extras, got rc=0 (name== regex likely missed the extras line)"
    elif [ -s "$PIP_LOG" ]; then
        fail "$name" "pip invoked on hashless-with-extras manifest"
    else
        pass "$name"
    fi
}
test_deps_hashless_extras

# ---------------------------------------------------------------------------
# TEST 7 — H1 hashed + https index -> --require-hashes AND no --trusted-host.
# ---------------------------------------------------------------------------
test_deps_hashed_https() {
    name="H1-hashed-https-require-hashes-no-trusted-host"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "install_python_deps unreachable: seam absent (main ran on source)"
        return
    fi
    h=$(setup_home "$SANDBOX/h-https")
    make_pip "$h/runtime/python/bin/pip"
    {
        printf 'requests==2.31.0 \\\n'
        printf '    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
    } > "$h/runtime/agents/requirements-frozen.txt"
    : > "$PIP_LOG"
    run_in_install '
        VULTURE_HOME="'"$h"'"
        VULTURE_PIP_INDEX_URL="https://pypi.org/simple"
        export VULTURE_HOME VULTURE_PIP_INDEX_URL
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    if [ ! -s "$PIP_LOG" ]; then
        fail "$name" "pip not invoked on a valid hashed manifest (rc=$rc)"
        return
    fi
    detail=""
    grep -q -- '--require-hashes' "$PIP_LOG" || detail="$detail missing --require-hashes;"
    if grep -q -- '--trusted-host' "$PIP_LOG"; then
        detail="$detail --trusted-host present for an https index (TLS silently disabled);"
    fi
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail pip argv: $(cat "$PIP_LOG" | tr '\n' '|' | cut -c1-160)"
    fi
}
test_deps_hashed_https

# ---------------------------------------------------------------------------
# TEST 8 — H1 explicit http:// index -> --trusted-host present.
# ---------------------------------------------------------------------------
test_deps_http_trusted() {
    name="H1-explicit-http-trusted-host"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "install_python_deps unreachable: seam absent (main ran on source)"
        return
    fi
    h=$(setup_home "$SANDBOX/h-http")
    make_pip "$h/runtime/python/bin/pip"
    {
        printf 'requests==2.31.0 \\\n'
        printf '    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
    } > "$h/runtime/agents/requirements-frozen.txt"
    : > "$PIP_LOG"
    run_in_install '
        VULTURE_HOME="'"$h"'"
        VULTURE_PIP_INDEX_URL="http://mirror.internal:8080/simple"
        export VULTURE_HOME VULTURE_PIP_INDEX_URL
        install_python_deps
    ' >/dev/null 2>&1
    if [ ! -s "$PIP_LOG" ]; then
        fail "$name" "pip not invoked on a valid hashed manifest with http index"
        return
    fi
    if grep -q -- '--trusted-host' "$PIP_LOG"; then
        pass "$name"
    else
        fail "$name" "no --trusted-host for an explicit http:// index; pip argv: $(cat "$PIP_LOG" | tr '\n' '|' | cut -c1-160)"
    fi
}
test_deps_http_trusted

# ---------------------------------------------------------------------------
# TEST 9 — A4/H4/H5 reject_if_system_dir.
# Rejects (non-zero) each blacklisted dir and a child like /usr/local;
# rejects /root exact; ALLOWS /root/.vulture, /home/alice/.vulture, /opt/vulture.
# ---------------------------------------------------------------------------
test_reject_system_dir() {
    name="A4-H4-H5-reject_if_system_dir"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "reject_if_system_dir unreachable: seam absent (H5 shared helper / main ran on source)"
        return
    fi
    rj="$SANDBOX/reject.out"
    : > "$rj"
    # Inside one sourced subshell: probe each dir, append result to $rj.
    run_in_install '
        if ! type reject_if_system_dir >/dev/null 2>&1; then
            echo "NO_FN" > "'"$rj"'"
            exit 0
        fi
        for d in / /etc /usr /var /bin /sbin /lib /boot /sys /proc /dev /root /usr/local; do
            ( reject_if_system_dir "$d" ) >/dev/null 2>&1
            if [ $? -eq 0 ]; then printf "FAILED-TO-REJECT(%s);" "$d" >> "'"$rj"'"; fi
        done
        for d in /root/.vulture /home/alice/.vulture /opt/vulture; do
            ( reject_if_system_dir "$d" ) >/dev/null 2>&1
            if [ $? -ne 0 ]; then printf "WRONGLY-REJECTED(%s);" "$d" >> "'"$rj"'"; fi
        done
        echo "DONE" >> "'"$rj"'"
    ' >/dev/null 2>&1
    detail=$(cat "$rj" 2>/dev/null)
    if [ "$detail" = "NO_FN" ] || ! grep -q DONE "$rj" 2>/dev/null; then
        fail "$name" "reject_if_system_dir: function not defined (H5 shared helper missing)"
    elif [ "$detail" = "DONE" ]; then
        pass "$name"
    else
        fail "$name" "${detail%DONE}"
    fi
}
test_reject_system_dir

# ---------------------------------------------------------------------------
# TEST 10 — A3 strip_quarantine removes .filelist on OS=linux.
# ---------------------------------------------------------------------------
test_strip_quarantine_linux() {
    name="A3-filelist-cleanup-linux"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "strip_quarantine unreachable: seam absent (main ran on source)"
        return
    fi
    h="$SANDBOX/h-quar"
    rm -rf "$h"; mkdir -p "$h"
    printf 'some/file\nother/file\n' > "$h/.filelist"
    run_in_install '
        VULTURE_HOME="'"$h"'"
        OS="linux"
        export VULTURE_HOME OS
        type strip_quarantine >/dev/null 2>&1 && strip_quarantine
    ' >/dev/null 2>&1
    if [ -e "$h/.filelist" ]; then
        fail "$name" ".filelist still present after strip_quarantine on OS=linux"
    else
        pass "$name"
    fi
}
test_strip_quarantine_linux

# ---------------------------------------------------------------------------
# TEST 11 — H2 commit_install deletes OLD_HOME + sets committed flag.
# ---------------------------------------------------------------------------
test_commit_install() {
    name="H2-commit_install-deletes-old-home"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "commit_install unreachable: seam absent (main ran on source)"
        return
    fi
    old="$SANDBOX/old-home"
    new="$SANDBOX/new-home"
    rm -rf "$old" "$new"
    mkdir -p "$old" "$new"
    printf 'old\n' > "$old/marker"
    flagfile="$SANDBOX/committed.flag"
    rm -f "$flagfile"
    run_in_install '
        VULTURE_HOME="'"$new"'"
        OLD_HOME="'"$old"'"
        export VULTURE_HOME OLD_HOME
        type commit_install >/dev/null 2>&1 && commit_install
        # Expose the committed flag for the parent: commit_install must set a
        # variable (COMMITTED / INSTALL_COMMITTED) to a truthy value.
        printf "%s" "${COMMITTED:-${INSTALL_COMMITTED:-}}" > "'"$flagfile"'"
    ' >/dev/null 2>&1
    if [ ! -f "$flagfile" ]; then
        fail "$name" "commit_install: function not defined / never reached"
        return
    fi
    detail=""
    if [ -d "$old" ]; then
        detail="$detail OLD_HOME not deleted;"
    fi
    if [ ! -s "$flagfile" ] || ! grep -Eqi '1|true|yes|committed' "$flagfile"; then
        detail="$detail committed flag not set;"
    fi
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
}
test_commit_install

# ---------------------------------------------------------------------------
# TEST 12 — H2 cleanup restores OLD_HOME -> VULTURE_HOME on uncommitted abort.
# ---------------------------------------------------------------------------
test_cleanup_rollback() {
    name="H2-cleanup-rollback-uncommitted"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "cleanup unreachable: seam absent (main ran on source)"
        return
    fi
    old="$SANDBOX/roll-old"
    target="$SANDBOX/roll-home"
    rm -rf "$old" "$target"
    # Simulate: old install was moved aside to OLD_HOME, new partial install at
    # VULTURE_HOME, then an abort happens BEFORE commit_install ran.
    mkdir -p "$old"
    printf 'ORIGINAL\n' > "$old/marker"
    mkdir -p "$target"
    printf 'PARTIAL\n' > "$target/marker"
    run_in_install '
        VULTURE_HOME="'"$target"'"
        OLD_HOME="'"$old"'"
        COMMITTED=""
        INSTALL_COMMITTED=""
        export VULTURE_HOME OLD_HOME COMMITTED INSTALL_COMMITTED
        type cleanup >/dev/null 2>&1 && cleanup
    ' >/dev/null 2>&1
    # After rollback, VULTURE_HOME should hold the ORIGINAL content again.
    if [ -f "$target/marker" ] && grep -q 'ORIGINAL' "$target/marker"; then
        pass "$name"
    else
        got="(missing)"
        [ -f "$target/marker" ] && got=$(cat "$target/marker")
        fail "$name" "OLD_HOME not restored to VULTURE_HOME on uncommitted abort; marker=$got"
    fi
}
test_cleanup_rollback

# ---------------------------------------------------------------------------
# TEST 13 — fresh-install rollback (review #3).
# On a FRESH install (no prior ~/.vulture, so OLD_HOME never set) that aborts
# after the swap, cleanup must remove the partial VULTURE_HOME. A swap marker
# (SWAPPED) distinguishes "we created it" from a pre-existing install.
# ---------------------------------------------------------------------------
test_cleanup_fresh_partial() {
    name="H2-cleanup-fresh-install-partial-removed"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "cleanup unreachable: seam absent"; return; fi
    target="$SANDBOX/fresh-home"; rm -rf "$target"; mkdir -p "$target"
    printf 'PARTIAL\n' > "$target/marker"
    run_in_install '
        VULTURE_HOME="'"$target"'"
        OLD_HOME=""; SWAPPED=1; COMMITTED=""; INSTALL_COMMITTED=""
        export VULTURE_HOME OLD_HOME SWAPPED COMMITTED INSTALL_COMMITTED
        type cleanup >/dev/null 2>&1 && cleanup
    ' >/dev/null 2>&1
    if [ ! -e "$target" ]; then pass "$name"
    else fail "$name" "partial VULTURE_HOME left on disk after a fresh-install abort"; fi
}
test_cleanup_fresh_partial

# TEST 14 — safety: a PRE-swap abort must NOT delete a pre-existing install
# (guards against an over-broad rm destroying a healthy install if, e.g., the
# download fails before extraction).
test_cleanup_preserves_preexisting() {
    name="H2-cleanup-preserves-untouched-home"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "cleanup unreachable: seam absent"; return; fi
    target="$SANDBOX/pre-home"; rm -rf "$target"; mkdir -p "$target"
    printf 'GOOD\n' > "$target/marker"
    run_in_install '
        VULTURE_HOME="'"$target"'"
        OLD_HOME=""; SWAPPED=""; COMMITTED=""; INSTALL_COMMITTED=""
        export VULTURE_HOME OLD_HOME SWAPPED COMMITTED INSTALL_COMMITTED
        type cleanup >/dev/null 2>&1 && cleanup
    ' >/dev/null 2>&1
    if [ -f "$target/marker" ] && grep -q GOOD "$target/marker"; then pass "$name"
    else fail "$name" "cleanup deleted a pre-existing install on a pre-swap abort"; fi
}
test_cleanup_preserves_preexisting

# TEST 15 — .filelist is POPULATED after extract (review #1). tar -v writes the
# list to stdout; capturing stderr instead leaves it empty and the macOS
# quarantine strip becomes a dead no-op.
test_filelist_populated() {
    name="A3-filelist-populated-after-extract"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "extract_atomic unreachable: seam absent"; return; fi
    src="$SANDBOX/tarsrc"; rm -rf "$src"; mkdir -p "$src/bin" "$src/runtime"
    printf 'x\n' > "$src/bin/vulture"; printf 'y\n' > "$src/runtime/data"
    tb="$SANDBOX/art.tar.gz"; ( cd "$src" && tar -czf "$tb" . ) 2>/dev/null
    home="$SANDBOX/extract-home"; rm -rf "$home" "$home.new"
    run_in_install '
        VULTURE_HOME="'"$home"'"; TARBALL="'"$tb"'"; OS=linux
        export VULTURE_HOME TARBALL OS
        type extract_atomic >/dev/null 2>&1 && extract_atomic
    ' >/dev/null 2>&1
    if [ -s "$home/.filelist" ]; then pass "$name"
    else fail "$name" ".filelist empty/absent after extract (tar verbose redirect bug)"; fi
}
test_filelist_populated

# TEST 16 — resolve_version GitHub-API curl carries a timeout (review #4 / H6).
test_resolve_version_timeout() {
    name="H6-resolve_version-curl-timeout"
    if sed -n '/^resolve_version()/,/^}/p' "$INSTALL_SH" | grep 'curl' | grep -q -- '--max-time'; then
        pass "$name"
    else
        fail "$name" "resolve_version curl has no --max-time (can hang on a stalled network)"
    fi
}
test_resolve_version_timeout

# TEST 17 — cosign required but absent must err (review #9 coverage).
test_cosign_required_absent() {
    name="A1-cosign-required-but-absent-errs"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "verify_signature unreachable"; return; fi
    empty="$SANDBOX/nopath"; mkdir -p "$empty"; rc=0
    run_in_install '
        PATH="'"$empty"'"; VULTURE_REQUIRE_COSIGN=true
        export PATH VULTURE_REQUIRE_COSIGN
        type verify_signature >/dev/null 2>&1 && verify_signature
    ' >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then pass "$name"
    else fail "$name" "verify_signature did not err with cosign required+absent"; fi
}
test_cosign_required_absent

# TEST 18 — anti-downgrade guard (review #9 coverage; also locks the
# sort-V → portable-awk refactor). older→err, override→ok, newer→ok.
test_downgrade_guard() {
    name="H2-downgrade-guard"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "resolve_version unreachable"; return; fi
    rc=0
    run_in_install 'VULTURE_VERSION="v0.0.1"; unset VULTURE_ALLOW_DOWNGRADE; export VULTURE_VERSION; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    older_errs=$rc; rc=0
    run_in_install 'VULTURE_VERSION="v0.0.1"; VULTURE_ALLOW_DOWNGRADE=true; export VULTURE_VERSION VULTURE_ALLOW_DOWNGRADE; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    override_ok=$rc; rc=0
    run_in_install 'VULTURE_VERSION="v9.9.9"; unset VULTURE_ALLOW_DOWNGRADE; export VULTURE_VERSION; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    newer_ok=$rc
    if [ "$older_errs" -ne 0 ] && [ "$override_ok" -eq 0 ] && [ "$newer_ok" -eq 0 ]; then pass "$name"
    else fail "$name" "older_errs=$older_errs override_ok=$override_ok newer_ok=$newer_ok"; fi
}
test_downgrade_guard

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
