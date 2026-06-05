#!/usr/bin/env sh
# Branch tests for install.sh (feature 0055 Tier A + hardening pass).
# Sources install.sh with VULTURE_INSTALL_SOURCE_ONLY=1 so main() does
# not run, stubs `cosign`/`pip` on PATH, and asserts argument shape +
# fail-closed / blacklist / rollback behaviour.
#
# Run: scripts/tests/test_install_sh.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0; FAIL=0
ok()   { echo "  PASS [$1]"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL [$1] $2"; FAIL=$((FAIL+1)); }

# Sandbox + PATH shims
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"; mkdir -p "$BIN"
cat > "$BIN/cosign" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$WORK/cosign.args"
exit 0
EOF
chmod +x "$BIN/cosign"
PATH="$BIN:$PATH"; export PATH

# Source the functions (main() suppressed). install.sh runs `set -eu`;
# neutralize it in the harness so our own control flow + the err()→exit
# paths (which we test in subshells) don't kill the script.
VULTURE_INSTALL_SOURCE_ONLY=1 . "$ROOT/install.sh"
set +e +u

echo "test_install_sh:"

# ── verify_signature: correct cosign arg shape (A1) ──────────────────
SHASUM_FILE="$WORK/SHA256SUMS"; : > "$SHASUM_FILE"
SIG_FILE="$WORK/SHA256SUMS.sig"; echo sig > "$SIG_FILE"
echo pem > "$WORK/SHA256SUMS.pem"
REPO_OWNER=bobinson; REPO_NAME=vulture; OS=linux
( verify_signature ) >/dev/null 2>&1
ARGS=$(cat "$WORK/cosign.args" 2>/dev/null)
# exactly one positional = the blob ($SHASUM_FILE); pem only via --certificate
if printf '%s\n' "$ARGS" | grep -qx "$SHASUM_FILE" \
   && printf '%s\n' "$ARGS" | grep -q -- '--certificate' \
   && printf '%s\n' "$ARGS" | grep -q -- '--signature' \
   && [ "$(printf '%s\n' "$ARGS" | grep -c "SHA256SUMS.pem$")" = "1" ]; then
  ok "verify_signature passes one positional + --certificate (no stray pem positional)"
else
  bad "verify_signature arg shape" "args: $ARGS"
fi

# ── verify_signature: no sig file → SHA-only (returns 0) ─────────────
rm -f "$WORK/cosign.args"; SIG_FILE="$WORK/missing.sig"
if ( verify_signature ) >/dev/null 2>&1 && [ ! -f "$WORK/cosign.args" ]; then
  ok "no signature → SHA-only, cosign not invoked"
else
  bad "no-sig branch" "cosign should not run"
fi

# ── install_python_deps: CLI-only build (no pip, no reqs) → success ──
VULTURE_HOME="$WORK/home"; mkdir -p "$VULTURE_HOME/runtime/agents"
if ( install_python_deps ) >/dev/null 2>&1; then
  ok "no pip + no reqs → CLI-only success (not an error)"
else
  bad "cli-only" "should return success"
fi

# ── install_python_deps: hashless non-empty reqs → fail closed ───────
mkdir -p "$VULTURE_HOME/runtime/python/bin"
cat > "$VULTURE_HOME/runtime/python/bin/pip" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$VULTURE_HOME/runtime/python/bin/pip"
printf 'fastapi==0.110.0\nhttpx==0.28.0\n' > "$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
if ( install_python_deps ) >/dev/null 2>&1; then
  bad "hashless fail-closed" "should err on hashless deps, but returned 0"
else
  ok "hashless non-empty reqs → fail closed (no silent hashless install)"
fi

# ── install_python_deps: hashless reqs with EXTRAS → still fail closed (#3) ──
# A narrow `^name==` check would miss `uvicorn[standard]==`; the line-based
# check must still catch it and refuse rather than fall through to an opaque
# pip --require-hashes failure.
printf '# pinned\nuvicorn[standard]==0.27.0\n' > "$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
if ( install_python_deps ) >/dev/null 2>&1; then
  bad "hashless extras fail-closed" "extras line slipped past the hashless check"
else
  ok "hashless reqs with extras → fail closed (#3 regex robustness)"
fi

# ── install_python_deps: hashed reqs (https index) → --require-hashes,
#    and NO --trusted-host (#1: https must keep TLS verification) ──────
cat > "$VULTURE_HOME/runtime/python/bin/pip" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$WORK/pip.args"
exit 0
EOF
chmod +x "$VULTURE_HOME/runtime/python/bin/pip"
printf 'fastapi==0.110.0 --hash=sha256:deadbeef\n' > "$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
( unset VULTURE_PIP_INDEX_URL; install_python_deps ) >/dev/null 2>&1
if grep -q -- '--require-hashes' "$WORK/pip.args" 2>/dev/null \
   && ! grep -q -- '--trusted-host' "$WORK/pip.args" 2>/dev/null; then
  ok "hashed reqs + https index → --require-hashes, NO --trusted-host (#1)"
else
  bad "hashed/https path" "args: $(cat "$WORK/pip.args" 2>/dev/null)"
fi

# ── install_python_deps: explicit http:// mirror → --trusted-host added (#1) ──
rm -f "$WORK/pip.args"
( VULTURE_PIP_INDEX_URL="http://mirror.local:8080/simple" install_python_deps ) >/dev/null 2>&1
if grep -q -- '--trusted-host' "$WORK/pip.args" 2>/dev/null \
   && grep -q 'mirror.local' "$WORK/pip.args" 2>/dev/null; then
  ok "http:// mirror → --trusted-host mirror.local (TLS opt-out only when plaintext)"
else
  bad "http mirror path" "args: $(cat "$WORK/pip.args" 2>/dev/null)"
fi

# ── reject_if_system_dir: blacklist correctness incl. /root carve-out (A4, #4) ──
REJECT_OK=1
for d in / /etc /usr /var /usr/local /var/lib /root /bin/foo; do
  reject_if_system_dir "$d" && { bad "blacklist" "$d should be rejected"; REJECT_OK=0; }
done
for d in /root/.vulture /home/alice/.vulture /opt/vulture "$WORK/home"; do
  reject_if_system_dir "$d" || { bad "blacklist" "$d should be ALLOWED"; REJECT_OK=0; }
done
[ "$REJECT_OK" = 1 ] && ok "reject_if_system_dir: system dirs rejected; /root/* + normal homes allowed (#4)"

# ── strip_quarantine: .filelist removed on Linux too (A3) ────────────
OS=linux
echo "x bin/vulture" > "$VULTURE_HOME/.filelist"
( strip_quarantine ) >/dev/null 2>&1
if [ ! -e "$VULTURE_HOME/.filelist" ]; then
  ok "strip_quarantine removes .filelist on Linux (A3)"
else
  bad "filelist cleanup" ".filelist still present on Linux"
fi

# ── commit_install + cleanup: durable swap vs rollback (#2) ──────────
# commit_install removes the retained old version and sets the committed flag.
RB="$WORK/rb"; mkdir -p "$RB/home" "$RB/home.old"
( VULTURE_HOME="$RB/home"; OLD_HOME="$RB/home.old"; INSTALL_COMMITTED=0
  commit_install
  [ ! -e "$RB/home.old" ] && [ "$INSTALL_COMMITTED" = 1 ] ) >/dev/null 2>&1
if [ $? -eq 0 ]; then
  ok "commit_install deletes OLD_HOME and marks the swap durable (#2)"
else
  bad "commit_install" "OLD_HOME not cleaned or flag not set"
fi

# cleanup() with an uncommitted swap must restore OLD_HOME → VULTURE_HOME.
rm -rf "$RB"; mkdir -p "$RB"
echo NEW > "$RB/home.marker.new"; mkdir -p "$RB/home"; mv "$RB/home.marker.new" "$RB/home/marker"
mkdir -p "$RB/home.old"; echo OLD > "$RB/home.old/marker"
( VULTURE_HOME="$RB/home"; OLD_HOME="$RB/home.old"; INSTALL_COMMITTED=0
  NEW_HOME=""; DL_TMP=""
  cleanup ) >/dev/null 2>&1
if [ "$(cat "$RB/home/marker" 2>/dev/null)" = OLD ] && [ ! -e "$RB/home.old" ]; then
  ok "cleanup rolls back to the previous version on an uncommitted abort (#2)"
else
  bad "cleanup rollback" "VULTURE_HOME not restored from OLD_HOME"
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
