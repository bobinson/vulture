#!/usr/bin/env sh
# Test for scripts/lib/hash.sh — sha256_of(). Run: sh scripts/tests/test_hash_sh.sh
set -u

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
PASS=0
FAIL=0

# shellcheck disable=SC1091
. "$REPO_ROOT/scripts/lib/hash.sh"

tmp=$(mktemp)
printf 'vulture sha256 helper test\n' > "$tmp"

# The helper must agree with whichever reference tool exists on this host.
if command -v sha256sum >/dev/null 2>&1; then
    expected=$(sha256sum "$tmp" | awk '{print $1}')
else
    expected=$(shasum -a 256 "$tmp" | awk '{print $1}')
fi

got=$(sha256_of "$tmp")
if [ "$got" = "$expected" ]; then
    echo "  PASS [matches reference tool]"; PASS=$((PASS + 1))
else
    echo "  FAIL [digest] got='$got' expected='$expected'"; FAIL=$((FAIL + 1))
fi

# Output must be exactly 64 lowercase hex chars (no filename / trailing junk).
case "$got" in
    *[!0-9a-f]*) echo "  FAIL [non-hex output: '$got']"; FAIL=$((FAIL + 1)) ;;
    *)
        if [ "${#got}" -eq 64 ]; then
            echo "  PASS [64 hex chars]"; PASS=$((PASS + 1))
        else
            echo "  FAIL [length ${#got} != 64]"; FAIL=$((FAIL + 1))
        fi ;;
esac

rm -f "$tmp"
echo "hash helper: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
