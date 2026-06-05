#!/usr/bin/env sh
# Branch tests for install.sh's verify_signature + install_python_deps
# (feature 0055 Tier A). Sources install.sh with VULTURE_INSTALL_SOURCE_ONLY=1
# so main() doesn't run, stubs `cosign`/`pip` on PATH, and asserts the
# argument shape + fail-closed behaviour.
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

# ── install_python_deps: hashed reqs → invokes pip --require-hashes ──
cat > "$VULTURE_HOME/runtime/python/bin/pip" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$WORK/pip.args"
exit 0
EOF
chmod +x "$VULTURE_HOME/runtime/python/bin/pip"
printf 'fastapi==0.110.0 --hash=sha256:deadbeef\n' > "$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
( install_python_deps ) >/dev/null 2>&1
if grep -q -- '--require-hashes' "$WORK/pip.args" 2>/dev/null; then
  ok "hashed reqs → pip install --require-hashes"
else
  bad "hashed path" "pip not invoked with --require-hashes"
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
