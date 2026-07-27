#!/usr/bin/env sh
# Test for scripts/check-ssh-version.sh — the 0065 §L2 OpenSSH >= 7.6 gate.
# Run: sh scripts/tests/test_check_ssh_version.sh
set -u

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CHECK="$REPO_ROOT/scripts/check-ssh-version.sh"
PASS=0
FAIL=0

# expect_pass BANNER  — the checker must accept this ssh -V banner (exit 0).
expect_pass() {
    if printf '%s\n' "$1" | sh "$CHECK" >/dev/null 2>&1; then
        echo "  PASS [accepts: $1]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [should accept: $1]"; FAIL=$((FAIL + 1))
    fi
}

# expect_fail BANNER  — the checker must reject this ssh -V banner (exit != 0).
expect_fail() {
    if printf '%s\n' "$1" | sh "$CHECK" >/dev/null 2>&1; then
        echo "  FAIL [should reject: $1]"; FAIL=$((FAIL + 1))
    else
        echo "  PASS [rejects: $1]"; PASS=$((PASS + 1))
    fi
}

# >= 7.6 must pass (accept-new is supported).
expect_pass "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024"
expect_pass "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4, OpenSSL 3.0.2 15 Mar 2022"
expect_pass "OpenSSH_7.6p1 Ubuntu-4ubuntu0.7, OpenSSL 1.0.2n  7 Dec 2017"

# < 7.6 must fail (accept-new unsupported → downgrade must be caught in CI).
expect_fail "OpenSSH_7.5p1, OpenSSL 1.0.2k-fips"
expect_fail "OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13, OpenSSL 1.0.1f 6 Jan 2014"

# Unparseable / missing OpenSSH banner must fail closed.
expect_fail "not an ssh version string"
expect_fail ""

# Custom minimum via first arg (should reject 8.0 when min is 9.0).
if printf 'OpenSSH_8.0p1\n' | sh "$CHECK" 9.0 >/dev/null 2>&1; then
    echo "  FAIL [custom min 9.0 should reject 8.0]"; FAIL=$((FAIL + 1))
else
    echo "  PASS [custom min 9.0 rejects 8.0]"; PASS=$((PASS + 1))
fi

echo "check-ssh-version: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
