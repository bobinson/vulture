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
REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
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

# ---------------------------------------------------------------------------
# make_python — fake host Python interpreter for the Tier B-lite
# (VULTURE_USE_SYSTEM_PYTHON) unit tests.  Zero network, zero real venv.
#
# Contract env-vars exercised by these tests (per 0055 LLD §4.3):
#   VULTURE_USE_SYSTEM_PYTHON (1|true)  — opt in to the system-Python branch
#   VULTURE_PYTHON                      — explicit interpreter path/name
#   VULTURE_PY_MIN_MINOR (default 12)   — minimum acceptable 3.x minor
#
# The shim faithfully answers every interpreter call install.sh's
# detect_system_python / create_system_venv / install_deps_system_venv make:
#
#   * version gate (§4.4): the installer asks the interpreter itself via
#     `sys.version_info` — it runs `<py> - <minor>` with a heredoc script on
#     stdin (argv[1] = required minor).  The shim reports its version from the
#     FAKE_PYVER env (e.g. 3.12 / 3.13 / 3.11) and exits 0 iff
#     major==3 && minor>=argv1, mirroring py_version_ok.  It also handles the
#     `-c 'import sys; assert sys.version_info[:2] >= (3,12)'` self-check.
#
#   * capability probe (§4.5): `<py> -c 'import venv, ensurepip'` succeeds.
#
#   * venv build (§4.5): `<py> -m venv [--copies] DIR` materialises
#       DIR/bin/python3          (interpreter recorder, honours FAKE_PYVER)
#       DIR/bin/python3.12        (same recorder; the Go-expected name)
#       DIR/bin/pip               (argv recorder -> $VENV_PIP_LOG)
#       DIR/pyvenv.cfg            (so a venv-at-path assert can key on it)
#
#   * dep install (§4.6): the venv's own pip is the argv recorder; the
#     interpreter's `-m pip ...` and import self-check (`<py> - <<PY`) succeed.
#
# VENV_PIP_LOG names the per-test argv log the venv-pip writes to; it is baked
# into the generated bin/pip at venv-creation time so it survives the
# launcher's restricted PATH.  Detection records resolved-interpreter argv to
# PY_DETECT_LOG (so "shim never invoked" can be asserted in U1).
# ---------------------------------------------------------------------------
PY_DETECT_LOG="$SANDBOX/py-detect.argv"
VENV_PIP_LOG="$SANDBOX/venv-pip.argv"
export VENV_PIP_LOG

make_python() {
    _dest=$1
    mkdir -p "$(dirname "$_dest")"
    cat > "$_dest" <<EOF
#!/usr/bin/env sh
# Fake Python interpreter shim (Tier B-lite tests).  Records its own argv so a
# test can assert the interpreter was (or was NOT) invoked.
printf '%s ' "\$@" >> "${PY_DETECT_LOG}"
printf '\n' >> "${PY_DETECT_LOG}"

# Resolve our version from FAKE_PYVER (default 3.12).  major.minor only.
_ver="\${FAKE_PYVER:-3.12}"
_major=\${_ver%%.*}
_minor=\${_ver#*.}
case "\$_minor" in *.*) _minor=\${_minor%%.*} ;; esac
[ "\$_major" = "\$_ver" ] && _minor=0

# --- subcommand dispatch -------------------------------------------------
case "\$1" in
  -)
    # Version/self-check or import self-check script arrives on STDIN.
    # The version gate passes the required minor as the FIRST positional and an
    # optional MAX minor as the SECOND ('<py> - <min> [<max>]').  If a numeric
    # arg is present, gate on [min,max]; otherwise this is an import self-check
    # (uvicorn/fastapi/...) -> just succeed.
    shift
    _need="\${1:-}"
    _needmax="\${2:-}"
    cat >/dev/null   # consume the heredoc body
    case "\$_need" in
      ''|*[!0-9]*) exit 0 ;;   # no numeric arg -> import self-check -> OK
    esac
    [ "\$_major" = "3" ] && [ "\$_minor" -ge "\$_need" ] || exit 1
    case "\$_needmax" in
      ''|*[!0-9]*) ;;                              # no max bound supplied
      *) [ "\$_minor" -le "\$_needmax" ] || exit 1 ;;
    esac
    exit 0
    ;;
  -c)
    # In-line code: capability probe ('import venv, ensurepip'), version
    # self-check ('assert sys.version_info[:2] >= (3,12)'), or import probe.
    _code="\${2:-}"
    case "\$_code" in
      *version_info*)
        if [ "\$_major" = "3" ] && [ "\$_minor" -ge 12 ]; then exit 0; fi
        exit 1
        ;;
      *) exit 0 ;;   # import venv,ensurepip / generic import -> OK
    esac
    ;;
  -m)
    case "\$2" in
      venv)
        # '<py> -m venv [--copies] DIR'  — DIR is the last arg.
        shift 2
        for _a in "\$@"; do _dir="\$_a"; done
        mkdir -p "\$_dir/bin"
        # pyvenv.cfg marks a real venv (venv-at-path assertion).
        printf 'home = %s\nversion = %s\n' "\$0" "\$_ver" > "\$_dir/pyvenv.cfg"
        # Interpreter recorders inside the venv (honour FAKE_PYVER): copy this
        # very shim so the venv python3/python3.12 behave identically.
        for _n in python3 python3.12 python; do
            cp "\$0" "\$_dir/bin/\$_n"
            chmod +x "\$_dir/bin/\$_n"
        done
        # The venv's pip is the argv recorder, writing the per-test log path
        # captured at venv-creation time.
        _vlog="\${VENV_PIP_LOG:-${VENV_PIP_LOG}}"
        cat > "\$_dir/bin/pip" <<PIPEOF
#!/usr/bin/env sh
printf '%s ' "\\\$@" >> "\$_vlog"
printf '\n' >> "\$_vlog"
exit 0
PIPEOF
        chmod +x "\$_dir/bin/pip"
        exit 0
        ;;
      pip)
        # '<py> -m pip install --upgrade pip' (intra-venv bootstrap) -> OK.
        exit 0
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
EOF
    chmod +x "$_dest"
}

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
# shellcheck disable=SC2016  # single-quoted on purpose: $SANDBOX expands inside install.sh, not here
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
# TEST 3 — verify_signature with cosign present but NO signature/cert.
# Security posture (0055 audit #6): cosign installed + missing sig is a
# downgrade signal, so verify must REFUSE (fail-closed) by default and only
# fall back to SHA-only when VULTURE_ALLOW_UNSIGNED=true. cosign must never be
# invoked when there is nothing to verify.
# ---------------------------------------------------------------------------
test_verify_nosig() {
    name="A1-no-sig-refuses-downgrade"
    if [ "$SEAM_OK" -ne 1 ]; then
        fail "$name" "verify_signature unreachable: seam absent (main ran on source)"
        return
    fi
    work="$SANDBOX/nosig"
    mkdir -p "$work"
    SHASUM_FILE="$work/SHA256SUMS"
    printf 'deadbeef  vulture\n' > "$SHASUM_FILE"
    # (a) Default (cosign stubbed on PATH, no .pem/.sig) -> refuse, no cosign.
    : > "$COSIGN_LOG"
    : > "$COSIGN_LOG.lines"
    run_in_install '
        SHASUM_FILE="'"$SHASUM_FILE"'"
        SIG_FILE="'"$work"'/SHA256SUMS.sig"
        REPO_OWNER="freedomledger"
        REPO_NAME="vulture"
        unset VULTURE_ALLOW_UNSIGNED
        export SHASUM_FILE SIG_FILE REPO_OWNER REPO_NAME
        verify_signature
    ' >/dev/null 2>&1
    rc=$?
    if [ -s "$COSIGN_LOG" ]; then
        fail "$name" "cosign was invoked despite missing signature"
    elif [ "$rc" -eq 0 ]; then
        fail "$name" "verify_signature returned 0 on missing sig with cosign present; expected fail-closed refusal"
    else
        pass "$name"
    fi

    # (b) Explicit opt-out VULTURE_ALLOW_UNSIGNED=true -> graceful SHA-only.
    name="A1b-no-sig-allow-unsigned-sha-only"
    : > "$COSIGN_LOG"
    run_in_install '
        SHASUM_FILE="'"$SHASUM_FILE"'"
        SIG_FILE="'"$work"'/SHA256SUMS.sig"
        REPO_OWNER="freedomledger"
        REPO_NAME="vulture"
        VULTURE_ALLOW_UNSIGNED=true
        export SHASUM_FILE SIG_FILE REPO_OWNER REPO_NAME VULTURE_ALLOW_UNSIGNED
        verify_signature
    ' >/dev/null 2>&1
    rc=$?
    if [ -s "$COSIGN_LOG" ]; then
        fail "$name" "cosign was invoked despite missing signature (should be SHA-only)"
    elif [ "$rc" -ne 0 ]; then
        fail "$name" "verify_signature returned non-zero ($rc) with ALLOW_UNSIGNED; expected graceful SHA-only"
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
        fail "$name" "$detail pip argv: $(tr '\n' '|' < "$PIP_LOG" | cut -c1-160)"
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
        fail "$name" "no --trusted-host for an explicit http:// index; pip argv: $(tr '\n' '|' < "$PIP_LOG" | cut -c1-160)"
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
    # shellcheck disable=SC2016  # '"$rj"' injects the outer value into the single-quoted probe
    run_in_install '
        if ! type reject_if_system_dir >/dev/null 2>&1; then
            echo "NO_FN" > "'"$rj"'"
            exit 0
        fi
        for d in / /etc /usr /var /bin /sbin /lib /boot /sys /proc /dev /root /usr/local /private/etc /private/var /private/var/log; do
            ( reject_if_system_dir "$d" ) >/dev/null 2>&1
            if [ $? -eq 0 ]; then printf "FAILED-TO-REJECT(%s);" "$d" >> "'"$rj"'"; fi
        done
        for d in /root/.vulture /home/alice/.vulture /opt/vulture /var/folders/ab/cd/T/vulture-smoke /private/var/folders/ab/cd/T/vulture-smoke; do
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
    # shellcheck disable=SC2016  # '"$new"'/'"$old"' inject outer values into the single-quoted block
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

# TEST 17 — install lock (G2): acquire succeeds with no lock, refuses when held.
test_install_lock() {
    name="G2-install-lock-mutex"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "acquire_install_lock unreachable: seam absent"; return; fi
    lhome="$SANDBOX/lock-home"; rm -rf "$lhome" "$lhome.lock"
    # (a) first acquire succeeds and creates the lock dir.
    rc1=0
    run_in_install '
        VULTURE_HOME="'"$lhome"'"; export VULTURE_HOME
        type acquire_install_lock >/dev/null 2>&1 && acquire_install_lock
    ' >/dev/null 2>&1 || rc1=$?
    if [ "$rc1" -ne 0 ]; then
        fail "$name" "first acquire failed (rc=$rc1) with no pre-existing lock"; return
    fi
    if [ ! -d "$lhome.lock" ]; then
        fail "$name" "acquire_install_lock did not create $lhome.lock"; return
    fi
    # (b) second acquire (lock dir present) must refuse with non-zero.
    rc2=0
    run_in_install '
        VULTURE_HOME="'"$lhome"'"; export VULTURE_HOME
        type acquire_install_lock >/dev/null 2>&1 && acquire_install_lock
    ' >/dev/null 2>&1 || rc2=$?
    rm -rf "$lhome.lock"
    if [ "$rc2" -ne 0 ]; then pass "$name"
    else fail "$name" "second acquire succeeded despite existing lock (rc=$rc2)"; fi
}
test_install_lock

# TEST 18 — quickstart order: print_summary lists 'start' before 'scan' (the
# service/daemon must be up before 'scan' submits to it).
test_summary_order() {
    name="UX-summary-start-before-scan"
    body=$(sed -n '/print_summary()/,/^}/p' "$INSTALL_SH")
    start_ln=$(printf '%s\n' "$body" | grep -n 'vulture start' | head -1 | cut -d: -f1)
    scan_ln=$(printf '%s\n' "$body" | grep -n 'vulture scan' | head -1 | cut -d: -f1)
    if [ -n "$start_ln" ] && [ -n "$scan_ln" ] && [ "$start_ln" -lt "$scan_ln" ]; then
        pass "$name"
    else
        fail "$name" "print_summary must list 'vulture start' before 'vulture scan' (start=$start_ln scan=$scan_ln)"
    fi
}
test_summary_order

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
# Pins a known FALLBACK_TAG inside the run so the test is independent of
# whatever fallback install.sh currently ships (which changes per release).
test_downgrade_guard() {
    name="H2-downgrade-guard"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "resolve_version unreachable"; return; fi
    rc=0
    run_in_install 'FALLBACK_TAG=v1.0.0; VULTURE_VERSION="v0.9.0"; unset VULTURE_ALLOW_DOWNGRADE; export VULTURE_VERSION; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    older_errs=$rc; rc=0
    run_in_install 'FALLBACK_TAG=v1.0.0; VULTURE_VERSION="v0.9.0"; VULTURE_ALLOW_DOWNGRADE=true; export VULTURE_VERSION VULTURE_ALLOW_DOWNGRADE; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    override_ok=$rc; rc=0
    run_in_install 'FALLBACK_TAG=v1.0.0; VULTURE_VERSION="v9.9.9"; unset VULTURE_ALLOW_DOWNGRADE; export VULTURE_VERSION; type resolve_version >/dev/null 2>&1 && resolve_version' >/dev/null 2>&1 || rc=$?
    newer_ok=$rc
    if [ "$older_errs" -ne 0 ] && [ "$override_ok" -eq 0 ] && [ "$newer_ok" -eq 0 ]; then pass "$name"
    else fail "$name" "older_errs=$older_errs override_ok=$override_ok newer_ok=$newer_ok"; fi
}
test_downgrade_guard

# ===========================================================================
# Tier B-lite — "Use an Existing System Python" (VULTURE_USE_SYSTEM_PYTHON).
#
# RED unit tests U1–U12 (0055 LLD §7.1).  The system-Python branch in
# install_python_deps() does NOT exist yet, so U2–U11 must FAIL because that
# branch is absent (not because of a harness error).  U1 and U12 are
# regression locks: the CURRENT default/bundled flow already satisfies them,
# so they may PASS today — this is called out explicitly per test.
#
# Shared setup: a $VULTURE_HOME with agents dir + a HASHED frozen lockfile and
# NO bundled pip (so the bundled branch is not taken); a make_python shim on a
# dedicated PATH.  Each test truncates the detect + venv-pip argv logs first.
# ===========================================================================

# Hashed lockfile (carries --hash= lines so reqs_have_hashes() is satisfied).
write_hashed_reqs() {
    _f=$1
    mkdir -p "$(dirname "$_f")"
    {
        printf 'requests==2.31.0 \\\n'
        printf '    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
    } > "$_f"
}

# Home with agents dir + hashed lockfile, NO bundled runtime/python/bin/pip.
setup_sys_home() {
    _h=$1
    rm -rf "$_h"
    mkdir -p "$_h/runtime/agents"   # deliberately no runtime/python/bin/pip
    write_hashed_reqs "$_h/runtime/agents/requirements-frozen.txt"
    printf '%s' "$_h"
}

reset_py_logs() { : > "$PY_DETECT_LOG"; : > "$VENV_PIP_LOG"; }

# A dedicated bin dir holding only the python shim(s) for these tests, so a
# test can construct a PATH that does (or does not) expose a system python.
PYBIN="$SANDBOX/pybin"
mkdir -p "$PYBIN"
make_python "$PYBIN/python3.12"
make_python "$PYBIN/python3"

# ---------------------------------------------------------------------------
# U1 — explicit-off-no-build (regression lock).
# RECONCILED for the v3 AUTO-detect default: under the new tri-state
# VULTURE_USE_SYSTEM_PYTHON semantics, an UNSET flag means AUTO (opt in when a
# hashed lockfile + python>=3.12 are present — see U-auto1), so "no opt-in =>
# no build" is now expressed via the EXPLICIT-OFF value (=0). The original U1
# intent (no opt-in => CLI-only, python/venv shims NEVER invoked) is preserved
# verbatim; only the trigger moves from `unset` to `=0`. The unset/AUTO case is
# covered by U-auto1 (builds) and U-auto2 (CLI-only when no python).
# Flag =0, no bundled pip, hashed reqs present -> CLI-only return 0; the
# python / venv shims are NEVER invoked.
# ---------------------------------------------------------------------------
test_u1_default_off() {
    name="U1-explicit-off-no-build"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u1-home")
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=0
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 (CLI-only) got rc=$rc;"
    [ -s "$PY_DETECT_LOG" ] && detail="$detail python shim invoked with flag off;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked with flag off;"
    printf '%s' "$out" | grep -Eqi 'cli|docker' || detail="$detail no CLI-only note;"
    if [ -z "$detail" ]; then pass "$name"; else fail "$name" "$detail"; fi
}
test_u1_default_off

# ---------------------------------------------------------------------------
# U2 — detects-and-uses-system-python.
# Flag on, hashed reqs, py3.12 shim on PATH -> resolves python, builds venv,
# runs the venv-pip (its argv log is non-empty).
# ---------------------------------------------------------------------------
test_u2_detect_and_use() {
    name="U2-detects-and-uses-system-python"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u2-home")
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 got rc=$rc;"
    [ -s "$PY_DETECT_LOG" ] || detail="$detail system python never resolved/invoked;"
    [ -s "$VENV_PIP_LOG" ] || detail="$detail venv-pip never invoked (no venv install);"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "system-Python branch absent: $detail"; fi
}
test_u2_detect_and_use

# ---------------------------------------------------------------------------
# U3 — venv-at-expected-runtime-path.
# The venv must be created at exactly $VULTURE_HOME/runtime/python (assert
# pyvenv.cfg + the shim-created bin/python3.12 there).
# ---------------------------------------------------------------------------
test_u3_venv_path() {
    name="U3-venv-at-expected-path"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u3-home")
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps
    ' >/dev/null 2>&1
    detail=""
    [ -f "$h/runtime/python/pyvenv.cfg" ] || detail="$detail no pyvenv.cfg at runtime/python;"
    [ -x "$h/runtime/python/bin/python3.12" ] || detail="$detail no bin/python3.12 at runtime/python;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "venv not built at \$VULTURE_HOME/runtime/python: $detail"; fi
}
test_u3_venv_path

# ---------------------------------------------------------------------------
# U4 — version-gate-rejects-3.11.
# FAKE_PYVER=3.11 -> err (non-zero) mentioning 3.12; no venv, no pip.
# ---------------------------------------------------------------------------
test_u4_reject_311() {
    name="U4-version-gate-rejects-3.11"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u4-home")
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.11
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -ne 0 ] || detail="$detail expected non-zero (refuse) on 3.11 got rc=0;"
    printf '%s' "$out" | grep -q '3\.12' || detail="$detail refusal did not mention 3.12;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built despite 3.11;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked despite 3.11;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "version gate absent: $detail"; fi
}
test_u4_reject_311

# ---------------------------------------------------------------------------
# U5 — version-gate-accepts-3.12-and-3.13 (>=, not ==).
# Both 3.12 and 3.13 hosts must proceed to a venv build.
# ---------------------------------------------------------------------------
test_u5_accept_312_313() {
    name="U5-version-gate-accepts-3.12-and-3.13"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    detail=""
    for v in 3.12 3.13; do
        h=$(setup_sys_home "$SANDBOX/u5-home-$v")
        reset_py_logs
        run_in_install '
            PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
            VULTURE_HOME="'"$h"'"
            VULTURE_USE_SYSTEM_PYTHON=1
            FAKE_PYVER='"$v"'
            export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
            install_python_deps
        ' >/dev/null 2>&1
        rc=$?
        [ "$rc" -eq 0 ] || detail="$detail [$v] rc=$rc;"
        [ -f "$h/runtime/python/pyvenv.cfg" ] || detail="$detail [$v] no venv built;"
    done
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "version gate not >= (rejected an accepted minor): $detail"; fi
}
test_u5_accept_312_313

# ---------------------------------------------------------------------------
# U-maxgate — version-gate-rejects-3.14 (the agent closure caps at <3.14:
# litellm Requires-Python <3.14). REQUIRE mode (opt-in) + FAKE_PYVER=3.14 ->
# err (non-zero) mentioning the supported 3.12/3.13 range; no venv, no pip.
# Regression for the darwin-amd64 smoke-install failure where AUTO picked the
# runner's python3.14 and the hash-pinned litellm had no 3.14 distribution.
# ---------------------------------------------------------------------------
test_umax_reject_314() {
    name="U-maxgate-version-gate-rejects-3.14"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/umax-home")
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.14
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -ne 0 ] || detail="$detail expected non-zero (refuse) on 3.14 got rc=0;"
    printf '%s' "$out" | grep -q '3\.13' || detail="$detail refusal did not mention the 3.13 ceiling;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built despite 3.14;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked despite 3.14;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "max version gate absent: $detail"; fi
}
test_umax_reject_314

# ---------------------------------------------------------------------------
# U-auto-max — AUTO (flag unset) on a host whose only Python is 3.14 ->
# SOFT CLI-only (rc 0, no venv, no pip, CLI-only note). AUTO must NOT abort the
# whole install just because the sole interpreter is above the closure ceiling.
# ---------------------------------------------------------------------------
test_uauto_max_cli_only_on_314() {
    name="U-auto-max-cli-only-on-3.14"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto-max-home")
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        FAKE_PYVER=3.14
        export PATH VULTURE_HOME FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 (soft CLI-only) got rc=$rc;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built on 3.14 under AUTO;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked on 3.14 under AUTO;"
    printf '%s' "$out" | grep -Eqi 'cli|docker' || detail="$detail no CLI-only note;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "AUTO did not degrade to CLI-only on 3.14: $detail"; fi
}
test_uauto_max_cli_only_on_314

# ---------------------------------------------------------------------------
# U6 — explicit-interpreter-path.
# VULTURE_PYTHON=<shim path> is honored over a PATH search (point it at a shim
# that is NOT on PATH; PATH carries no python at all).
# ---------------------------------------------------------------------------
test_u6_explicit_interp() {
    name="U6-explicit-interpreter-path"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u6-home")
    # A python shim in a directory deliberately OFF the search PATH.
    explicit="$SANDBOX/u6-explicit/mypython"
    make_python "$explicit"
    cleanpath="$SANDBOX/u6-clean"; mkdir -p "$cleanpath"
    # Provide the basic utilities install.sh needs (sed/grep/...) via SHIMBIN's
    # parent dirs; keep python OFF it by using only system bins + SHIMBIN
    # (which has cosign/curl/pip but no python).
    reset_py_logs
    run_in_install '
        PATH="'"$SHIMBIN"':/usr/bin:/bin"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        VULTURE_PYTHON="'"$explicit"'"
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON VULTURE_PYTHON FAKE_PYVER
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail rc=$rc;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] || detail="$detail VULTURE_PYTHON not honored (no venv);"
    grep -q -- "$explicit" "$PY_DETECT_LOG" 2>/dev/null \
        || [ -s "$PY_DETECT_LOG" ] || detail="$detail explicit interpreter never invoked;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "VULTURE_PYTHON not recognized: $detail"; fi
}
test_u6_explicit_interp

# ---------------------------------------------------------------------------
# U7 — no-python-found-errs.
# Flag on, NO python on PATH and no VULTURE_PYTHON -> err; no venv/pip.
# ---------------------------------------------------------------------------
test_u7_no_python() {
    name="U7-no-python-found-errs"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u7-home")
    nopy="$SANDBOX/u7-nopy"; mkdir -p "$nopy"
    # Copy ONLY the non-python shims (cosign/curl/pip) so install.sh utilities
    # work but command -v pythonX finds nothing.  Real /usr/bin is excluded so
    # a host python3 cannot leak in.
    cp "$SHIMBIN/cosign" "$SHIMBIN/curl" "$SHIMBIN/pip" "$SHIMBIN/pip3" "$nopy/" 2>/dev/null
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$nopy"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        unset VULTURE_PYTHON
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -ne 0 ] || detail="$detail expected err (no python) got rc=0;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built with no python;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked with no python;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "no-python fall-through not fail-closed: $detail (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-100))"; fi
}
test_u7_no_python

# ---------------------------------------------------------------------------
# U8 — fail-closed-no-lockfile ("no unhashed escape hatch" lock).
# Flag on, hashLESS / empty requirements-frozen.txt -> err; venv-pip NOT
# invoked with an install.
# ---------------------------------------------------------------------------
test_u8_failclosed_no_lockfile() {
    name="U8-fail-closed-no-lockfile"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u8-home")
    # Overwrite with a hashLESS (but non-empty) manifest: real requirement
    # lines, zero --hash= -> must fail closed, never silently install unhashed.
    {
        printf 'requests==2.31.0\n'
        printf 'uvicorn[standard]==0.30.0\n'
    } > "$h/runtime/agents/requirements-frozen.txt"
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -ne 0 ] || detail="$detail expected err on hashless lockfile got rc=0 (unhashed escape hatch present!);"
    if grep -q -- 'install' "$VENV_PIP_LOG" 2>/dev/null; then detail="$detail venv-pip ran an install on a hashless lockfile;"; fi
    printf '%s' "$out" | grep -Eqi 'hash|lockfile|frozen' || detail="$detail refusal did not mention hashes/lockfile;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "fail-closed-no-lockfile not enforced: $detail"; fi
}
test_u8_failclosed_no_lockfile

# ---------------------------------------------------------------------------
# U9 — require-hashes-always.
# Flag on, hashed reqs, default https index -> venv-pip argv contains
# --require-hashes AND --only-binary :all: AND NO --trusted-host.
# ---------------------------------------------------------------------------
test_u9_require_hashes() {
    name="U9-require-hashes-always"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u9-home")
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        VULTURE_PIP_INDEX_URL="https://pypi.org/simple"
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER VULTURE_PIP_INDEX_URL
        install_python_deps
    ' >/dev/null 2>&1
    if [ ! -s "$VENV_PIP_LOG" ]; then
        fail "$name" "venv-pip never invoked (system-Python install branch absent)"; return
    fi
    detail=""
    grep -q -- '--require-hashes' "$VENV_PIP_LOG" || detail="$detail missing --require-hashes;"
    grep -q -- '--only-binary :all:' "$VENV_PIP_LOG" || detail="$detail missing --only-binary :all:;"
    grep -q -- '--trusted-host' "$VENV_PIP_LOG" && detail="$detail --trusted-host present for https index;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "$detail venv-pip argv: $(tr '\n' '|' < "$VENV_PIP_LOG" | cut -c1-160)"; fi
}
test_u9_require_hashes

# ---------------------------------------------------------------------------
# U10 — http-index-trusted-host.
# VULTURE_PIP_INDEX_URL=http://mirror:8080/simple + hashed reqs -> argv has
# --trusted-host mirror, still --require-hashes.
# ---------------------------------------------------------------------------
test_u10_http_trusted() {
    name="U10-http-index-trusted-host"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u10-home")
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        VULTURE_PIP_INDEX_URL="http://mirror:8080/simple"
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER VULTURE_PIP_INDEX_URL
        install_python_deps
    ' >/dev/null 2>&1
    if [ ! -s "$VENV_PIP_LOG" ]; then
        fail "$name" "venv-pip never invoked (system-Python install branch absent)"; return
    fi
    detail=""
    grep -q -- '--require-hashes' "$VENV_PIP_LOG" || detail="$detail missing --require-hashes;"
    grep -Eq -- '--trusted-host (mirror|mirror:8080)' "$VENV_PIP_LOG" \
        || detail="$detail missing --trusted-host mirror;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "$detail venv-pip argv: $(tr '\n' '|' < "$VENV_PIP_LOG" | cut -c1-160)"; fi
}
test_u10_http_trusted

# ---------------------------------------------------------------------------
# U11 — idempotent-rerun.
# Two installs into the SAME $VULTURE_HOME both succeed; no abort on the
# existing venv.
# ---------------------------------------------------------------------------
test_u11_idempotent() {
    name="U11-idempotent-rerun"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u11-home")
    _run() {
        reset_py_logs
        run_in_install '
            PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
            VULTURE_HOME="'"$h"'"
            VULTURE_USE_SYSTEM_PYTHON=1
            FAKE_PYVER=3.12
            export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
            install_python_deps
        ' >/dev/null 2>&1
    }
    _run; rc1=$?
    _run; rc2=$?   # second run over an existing venv must not abort
    detail=""
    [ "$rc1" -eq 0 ] || detail="$detail first run rc=$rc1;"
    [ "$rc2" -eq 0 ] || detail="$detail re-run aborted rc=$rc2;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] || detail="$detail venv missing after re-run;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "not idempotent: $detail"; fi
}
test_u11_idempotent

# ---------------------------------------------------------------------------
# U12 — bundled-python-wins-over-flag (precedence lock).
# Bundled runtime/python/bin/pip present AND flag set -> the BUNDLED path is
# used; no fresh system venv built and the system python shim is not invoked.
# NOTE: the CURRENT bundled branch is taken first ([ -x "$PIP" ]) and never
# touches the system-python code, so U12 may PASS today.
# ---------------------------------------------------------------------------
test_u12_bundled_wins() {
    name="U12-bundled-python-wins-over-flag"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/u12-home")
    # Make a bundled pip recorder (separate from the venv-pip log) present.
    make_pip "$h/runtime/python/bin/pip"
    : > "$PIP_LOG"
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail rc=$rc;"
    [ -s "$PIP_LOG" ] || detail="$detail bundled pip NOT used (precedence wrong);"
    [ -s "$PY_DETECT_LOG" ] && detail="$detail system python invoked despite bundled present;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail fresh system venv built despite bundled present;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "bundled-wins precedence violated: $detail"; fi
}
test_u12_bundled_wins

# U13 — cleanup() must return 0 on a clean/committed exit. The EXIT trap's last
# command status becomes the script's exit code; on the OFFLINE path DOWNLOAD_DIR
# is never set, so a trailing `[ -n "${DOWNLOAD_DIR:-}" ] && rm` evaluates false
# and a successful install would exit non-zero. (Caught by the cross-distro e2e.)
test_cleanup_returns_zero() {
    name="H2-cleanup-returns-zero-on-clean-exit"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "cleanup unreachable: seam absent"; return; fi
    rc=0
    run_in_install 'COMMITTED=1; INSTALL_COMMITTED=1; export COMMITTED INSTALL_COMMITTED; cleanup' >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then pass "$name"
    else fail "$name" "cleanup returned $rc on a committed no-op — a successful offline install would exit non-zero"; fi
}
test_cleanup_returns_zero

# ===========================================================================
# v3 — AUTO-detect system Python (tri-state VULTURE_USE_SYSTEM_PYTHON).
#
# New DEFAULT (flag UNSET/empty) is AUTO: if a hashed lockfile AND a host
# Python >= 3.12 are present, the system-Python venv is built and deps
# installed; otherwise a clean CLI-only fall-through (exit 0, no error).
# Tri-state: "0"/"false"/"no" DISABLE -> CLI-only; "1"/"true" REQUIRE ->
# strict (errors on missing python/lockfile); unset/empty -> AUTO.
# ===========================================================================

# ---------------------------------------------------------------------------
# U-auto1 — unset flag + hashed lockfile + python>=3.12 on PATH -> venv built
# and the venv-pip install is invoked (AUTO opts IN automatically).
# ---------------------------------------------------------------------------
test_uauto1_auto_builds() {
    name="U-auto1-auto-builds-when-python-present"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto1-home")
    reset_py_logs
    run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        unset VULTURE_USE_SYSTEM_PYTHON
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME FAKE_PYVER
        install_python_deps
    ' >/dev/null 2>&1
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 got rc=$rc;"
    [ -s "$PY_DETECT_LOG" ] || detail="$detail system python never resolved (AUTO did not detect);"
    [ -s "$VENV_PIP_LOG" ] || detail="$detail venv-pip never invoked (AUTO did not install);"
    [ -f "$h/runtime/python/pyvenv.cfg" ] || detail="$detail no venv built under AUTO;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "AUTO default did not build/install: $detail"; fi
}
test_uauto1_auto_builds

# ---------------------------------------------------------------------------
# U-auto2 — unset flag + NO python found -> CLI-only, exit 0, NO error
# (AUTO fails soft, never aborts the install).
# ---------------------------------------------------------------------------
test_uauto2_auto_no_python() {
    name="U-auto2-auto-no-python-cli-only"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto2-home")
    nopy="$SANDBOX/uauto2-nopy"; mkdir -p "$nopy"
    cp "$SHIMBIN/cosign" "$SHIMBIN/curl" "$SHIMBIN/pip" "$SHIMBIN/pip3" "$nopy/" 2>/dev/null
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$nopy"'"
        VULTURE_HOME="'"$h"'"
        unset VULTURE_USE_SYSTEM_PYTHON VULTURE_PYTHON
        export PATH VULTURE_HOME
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 (CLI-only soft) got rc=$rc;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built despite no python;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked despite no python;"
    printf '%s' "$out" | grep -Eqi 'cli|docker|python' || detail="$detail no CLI-only note;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "AUTO-no-python not a soft CLI-only fall-through: $detail"; fi
}
test_uauto2_auto_no_python

# ---------------------------------------------------------------------------
# U-auto3 — VULTURE_USE_SYSTEM_PYTHON=0 + python present -> CLI-only (DISABLED).
# Explicit opt-out must NOT build a venv even though a suitable python exists.
# ---------------------------------------------------------------------------
test_uauto3_disabled() {
    name="U-auto3-explicit-disable-cli-only"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto3-home")
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=0
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 (disabled) got rc=$rc;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built despite explicit disable;"
    [ -s "$VENV_PIP_LOG" ] && detail="$detail venv-pip invoked despite explicit disable;"
    printf '%s' "$out" | grep -Eqi 'cli|docker' || detail="$detail no CLI-only note;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "explicit disable (=0) not honored: $detail"; fi
}
test_uauto3_disabled

# ---------------------------------------------------------------------------
# U-auto4 — VULTURE_USE_SYSTEM_PYTHON=1 + NO python -> errs (strict preserved).
# REQUIRE mode keeps the current fail-closed behavior (regression lock for U7).
# ---------------------------------------------------------------------------
test_uauto4_require_no_python() {
    name="U-auto4-require-no-python-errs"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto4-home")
    nopy="$SANDBOX/uauto4-nopy"; mkdir -p "$nopy"
    cp "$SHIMBIN/cosign" "$SHIMBIN/curl" "$SHIMBIN/pip" "$SHIMBIN/pip3" "$nopy/" 2>/dev/null
    reset_py_logs
    rc=0
    run_in_install '
        PATH="'"$nopy"'"
        VULTURE_HOME="'"$h"'"
        VULTURE_USE_SYSTEM_PYTHON=1
        unset VULTURE_PYTHON
        export PATH VULTURE_HOME VULTURE_USE_SYSTEM_PYTHON
        install_python_deps
    ' >/dev/null 2>&1 || rc=$?
    detail=""
    [ "$rc" -ne 0 ] || detail="$detail expected err (REQUIRE+no python) got rc=0;"
    [ -f "$h/runtime/python/pyvenv.cfg" ] && detail="$detail venv built with no python;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "REQUIRE strictness not preserved: $detail"; fi
}
test_uauto4_require_no_python

# ---------------------------------------------------------------------------
# U-auto5 — AUTO + present-but-hashLESS lockfile -> warn + CLI-only, exit 0
# (NOT a hard error). AUTO refuses an unverified install but must not abort.
# ---------------------------------------------------------------------------
test_uauto5_auto_hashless_soft() {
    name="U-auto5-auto-hashless-soft-cli-only"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "install_python_deps unreachable: seam absent"; return; fi
    h=$(setup_sys_home "$SANDBOX/uauto5-home")
    # Overwrite the hashed lockfile with a hashLESS (non-empty) one.
    {
        printf 'requests==2.31.0\n'
        printf 'uvicorn[standard]==0.30.0\n'
    } > "$h/runtime/agents/requirements-frozen.txt"
    reset_py_logs
    out=$(run_in_install '
        PATH="'"$PYBIN"':'"$SHIMBIN"':'"$PATH"'"
        VULTURE_HOME="'"$h"'"
        unset VULTURE_USE_SYSTEM_PYTHON
        FAKE_PYVER=3.12
        export PATH VULTURE_HOME FAKE_PYVER
        install_python_deps 2>&1
    ')
    rc=$?
    detail=""
    [ "$rc" -eq 0 ] || detail="$detail expected rc 0 (soft) got rc=$rc (AUTO must not abort on hashless);"
    grep -q -- 'install' "$VENV_PIP_LOG" 2>/dev/null && detail="$detail venv-pip ran an install on a hashless lockfile;"
    [ -s "$out" ] || true
    printf '%s' "$out" | grep -Eqi 'cli|docker' || detail="$detail no CLI-only note;"
    if [ -z "$detail" ]; then pass "$name"
    else fail "$name" "AUTO-hashless not a soft refusal: $detail"; fi
}
test_uauto5_auto_hashless_soft

# ---------------------------------------------------------------------------
# msg — cli_only_note must NOT claim "skills still work" (audit #4/#6). The
# CLI + UI work, but agent/skill SCANNING needs a local Python runtime or
# Docker; skills run only inside the Python agents.
# ---------------------------------------------------------------------------
test_msg_cli_only_no_skills_claim() {
    name="msg-cli-only-no-skills-still-work-claim"
    if [ "$SEAM_OK" -ne 1 ]; then fail "$name" "cli_only_note unreachable: seam absent"; return; fi
    out=$(run_in_install 'type cli_only_note >/dev/null 2>&1 && cli_only_note 2>&1')
    if printf '%s' "$out" | grep -Eqi 'skills (still|also)? *work|cli \+ skills'; then
        fail "$name" "cli_only_note still claims skills work without agents: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-160)"
    elif printf '%s' "$out" | grep -Eqi 'docker|python'; then
        pass "$name"
    else
        fail "$name" "cli_only_note missing the Docker/Python guidance: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-160)"
    fi
}
test_msg_cli_only_no_skills_claim

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
