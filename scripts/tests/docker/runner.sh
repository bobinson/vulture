#!/usr/bin/env sh
# Runs INSIDE the test container: invoke install.sh offline, then assert the
# per-scenario outcome. Exits 0 (pass) / 1 (fail). Driven by run-one.sh.
#
# Inputs (env): SCENARIO, plus the install.sh offline knobs are set here.
# Mounts: /repo (repo, ro), /fix (fixture dir, ro).
set -u

SCENARIO=${SCENARIO:?SCENARIO required}
VHOME="$HOME/.vulture"
OUT=/tmp/install.out

pass() { echo "PASS [$SCENARIO] $*"; exit 0; }
fail() { echo "FAIL [$SCENARIO] $*"; echo "----- install output -----"; sed 's/^/  /' "$OUT" 2>/dev/null; exit 1; }

# Offline install knobs (no network for resolve/download; SHA-only verify).
export VULTURE_HOME="$VHOME"
export VULTURE_VERSION=v0.1.0            # skip the GitHub-API call in resolve_version
export VULTURE_OFFLINE_TARBALL=/fix/vulture.tar.gz
export VULTURE_ALLOW_UNSIGNED=true

case "$SCENARIO" in
    py-optin-hashed|py-optin-hashless|py-no-venv)
        export VULTURE_USE_SYSTEM_PYTHON=1 ;;
esac

rc=0
sh /repo/install.sh >"$OUT" 2>&1 || rc=$?

venv_built() { [ -f "$VHOME/runtime/python/pyvenv.cfg" ] && [ -x "$VHOME/runtime/python/bin/python3.12" ]; }

case "$SCENARIO" in
    no-python|py-no-optin)
        # CLI-only success: binary installed, NO venv, the honest note printed.
        [ "$rc" -eq 0 ] || fail "expected CLI-only success, rc=$rc"
        [ -f "$VHOME/bin/vulture" ] || fail "bin/vulture missing"
        [ -f "$VHOME/VERSION" ] || fail "VERSION missing"
        venv_built && fail "venv was built but should not be (CLI-only)"
        grep -qi 'web UI are installed' "$OUT" || fail "missing CLI-only note"
        # doctor reports python WARN (rc 2) but install succeeded
        "$VHOME/bin/vulture" doctor >/dev/null 2>&1; drc=$?
        [ "$drc" -eq 2 ] || fail "doctor expected WARN(2) for CLI-only, got $drc"
        pass "CLI-only install OK; no venv; doctor=2"
        ;;
    py-optin-hashed)
        # System-Python venv + hash-pinned deps installed; doctor flips to OK.
        [ "$rc" -eq 0 ] || fail "expected success, rc=$rc"
        venv_built || fail "venv not built at runtime/python"
        "$VHOME/runtime/python/bin/python3.12" -c 'import fastapi, uvicorn, pydantic, pydantic_core' 2>/dev/null \
            || fail "hash-pinned agent deps (fastapi/uvicorn/pydantic) not importable from the venv"
        "$VHOME/bin/vulture" doctor >/dev/null 2>&1; drc=$?
        [ "$drc" -eq 0 ] || fail "doctor expected OK(0) after venv install, got $drc"
        pass "system-Python venv built; --require-hashes dep importable; doctor=0"
        ;;
    py-optin-hashless)
        # Fail-closed: no unhashed escape hatch.
        [ "$rc" -ne 0 ] || fail "expected fail-closed (rc!=0) on hashless lockfile, got 0"
        grep -qiE 'hash|lockfile|frozen' "$OUT" || fail "refusal did not mention hashes"
        venv_built && [ -x "$VHOME/runtime/python/bin/pip" ] && \
            "$VHOME/runtime/python/bin/python3.12" -c 'import pathspec' 2>/dev/null \
            && fail "deps were installed despite hashless lockfile"
        pass "fail-closed on hashless lockfile (rc=$rc)"
        ;;
    py-no-venv)
        # Ubuntu: python3 present but python3-venv missing -> clean err, no half-install.
        [ "$rc" -ne 0 ] || fail "expected err when venv module missing, got 0"
        grep -qiE 'venv|ensurepip|python3-venv' "$OUT" || fail "error did not name the venv module"
        pass "fail-closed when python3-venv missing (rc=$rc)"
        ;;
    *)
        fail "unknown scenario"
        ;;
esac
