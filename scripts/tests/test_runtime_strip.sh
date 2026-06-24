#!/usr/bin/env sh
#
# Tests for scripts/lib/runtime_strip.sh — the bundled-runtime copyleft strip +
# regression guard (keeps the native installer permissive-only).
#
# PBS's _dbm extension (dbm.ndbm) links GNU gdbm (GPL-3.0) on macOS / Berkeley DB
# on Linux. Nothing in Vulture uses dbm.ndbm (dbm.open() falls back to the
# pure-Python dbm.dumb), so build-release.sh strips _dbm and asserts no copyleft
# native code remains. These tests exercise the strip + the guard on fixtures and
# assert build-release.sh actually wires them in.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# lib.sh pass()/fail() counters, a final tally, exit 1 on any FAIL.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
LIB="$REPO_ROOT/scripts/lib/runtime_strip.sh"
BR="$REPO_ROOT/scripts/build-release.sh"

require_file_or_bail "runtime_strip-lib-present" "$LIB"
# shellcheck source=scripts/lib/runtime_strip.sh
. "$LIB"

make_sandbox
RT="$SANDBOX/runtime/python"
DL="$RT/lib/python3.12/lib-dynload"

# reset_fixture — a clean lib-dynload with one benign (non-copyleft) module.
reset_fixture() {
    rm -rf "$RT"; mkdir -p "$DL"
    printf 'benign extension, OpenSSL 3.x\n' > "$DL/_ssl.cpython-312-x86_64-linux-gnu.so"
}

# 1. strip removes _dbm, keeps the benign module.
reset_fixture
printf 'fake dbm module\n' > "$DL/_dbm.cpython-312-x86_64-linux-gnu.so"
strip_copyleft_modules "$RT"
if [ ! -e "$DL/_dbm.cpython-312-x86_64-linux-gnu.so" ]; then
    pass "strip-removes-_dbm"
else
    fail "strip-removes-_dbm" "_dbm.*.so still present after strip"
fi
if [ -e "$DL/_ssl.cpython-312-x86_64-linux-gnu.so" ]; then
    pass "strip-keeps-other-modules"
else
    fail "strip-keeps-other-modules" "strip removed a non-_dbm module"
fi

# 2. strip is idempotent / safe when _dbm is already absent.
reset_fixture
if strip_copyleft_modules "$RT"; then pass "strip-idempotent"; else fail "strip-idempotent" "non-zero on clean dir"; fi

# 3. the guard PASSES on a copyleft-free runtime.
reset_fixture
if assert_no_copyleft_native "$RT" >/dev/null 2>&1; then
    pass "guard-passes-clean"
else
    fail "guard-passes-clean" "guard flagged a clean runtime"
fi

# 4. the guard FAILS when a module carries GNU gdbm (GPL-3.0) — the real risk.
reset_fixture
printf 'init dbm\nGNU gdbm 1.x\n' > "$DL/_dbm.cpython-312-darwin.so"
if assert_no_copyleft_native "$RT" >/dev/null 2>&1; then
    fail "guard-detects-gdbm" "guard did NOT detect GNU gdbm"
else
    pass "guard-detects-gdbm"
fi

# 5. the real flow: strip THEN guard leaves a clean, passing runtime.
reset_fixture
printf 'GNU gdbm\n' > "$DL/_dbm.cpython-312-darwin.so"
strip_copyleft_modules "$RT"
if assert_no_copyleft_native "$RT" >/dev/null 2>&1; then
    pass "strip-then-guard-clean"
else
    fail "strip-then-guard-clean" "copyleft remained after strip"
fi

# 6. build-release.sh actually wires the strip + guard into the bundle path.
assert_file_matches "build-release-sources-lib" "$BR" \
    'scripts/lib/runtime_strip\.sh' \
    "build-release.sh does not source runtime_strip.sh"
assert_file_matches "build-release-calls-strip" "$BR" \
    'strip_copyleft_modules' \
    "build-release.sh never calls strip_copyleft_modules"
assert_file_matches "build-release-calls-guard" "$BR" \
    'assert_no_copyleft_native' \
    "build-release.sh never calls the copyleft guard"

finish
