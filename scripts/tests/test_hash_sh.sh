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

# ---------------------------------------------------------------------------
# sha256_verify_in_sums() — verify a file against a SHA256SUMS entry keyed on the
# file's basename. The realistic input is a python-build-standalone asset name,
# which contains BOTH '+' (an ERE quantifier) and '.' (ERE any-char) — exactly
# the chars that make the old `grep -E "[[:space:]]<base>$"` selection unsafe.
# These cases pin the EXACT-field-match (awk $2==base) behaviour and catch a
# regression to the regex selector. Run in a private sandbox dir.
# ---------------------------------------------------------------------------
svis_dir=$(mktemp -d)

# A REALISTIC PBS filename WITH '+' and '.'.
SVIS_NAME='cpython-3.12.13+20260610-linux-amd64-install_only.tar.gz'
printf 'vendored pbs payload\n' > "$svis_dir/$SVIS_NAME"
SVIS_SHA=$(sha256_of "$svis_dir/$SVIS_NAME")

# A DECOY whose name is a regex-coincidence of $SVIS_NAME under the OLD grep:
# '.' is matched by the literal 'X' (ERE any-char) and '13+' is matched by '133'
# (ERE one-or-more '3'). So `grep -E "[[:space:]]${SVIS_NAME}$"` MATCHES this
# decoy line — but an exact awk `$2==base` match must NOT. (Verified: this name
# is matched by the old ERE, so case (d) below genuinely catches the B2 regex.)
SVIS_DECOY='cpython-3X12X13320260610-linux-amd64-install_onlyXtarXgz'
printf 'unrelated decoy payload\n' > "$svis_dir/$SVIS_DECOY"
SVIS_DECOY_SHA=$(sha256_of "$svis_dir/$SVIS_DECOY")

# (a) PASSES for the correct file + hash.
printf '%s  %s\n' "$SVIS_SHA" "$SVIS_NAME" > "$svis_dir/SHA256SUMS"
if ( cd "$svis_dir" && sha256_verify_in_sums "$SVIS_NAME" SHA256SUMS ) >/dev/null 2>&1; then
    echo "  PASS [verify_in_sums: correct file+hash accepted]"; PASS=$((PASS + 1))
else
    echo "  FAIL [verify_in_sums: correct file+hash rejected]"; FAIL=$((FAIL + 1))
fi

# (b) FAILS on a tampered hash (digest mismatch).
printf '%s  %s\n' "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" "$SVIS_NAME" > "$svis_dir/SHA256SUMS"
if ( cd "$svis_dir" && sha256_verify_in_sums "$SVIS_NAME" SHA256SUMS ) >/dev/null 2>&1; then
    echo "  FAIL [verify_in_sums: tampered hash was accepted]"; FAIL=$((FAIL + 1))
else
    echo "  PASS [verify_in_sums: tampered hash rejected]"; PASS=$((PASS + 1))
fi

# (c) FAILS when the basename has no line in SHA256SUMS.
printf '%s  %s\n' "$SVIS_DECOY_SHA" "$SVIS_DECOY" > "$svis_dir/SHA256SUMS"
if ( cd "$svis_dir" && sha256_verify_in_sums "$SVIS_NAME" SHA256SUMS ) >/dev/null 2>&1; then
    echo "  FAIL [verify_in_sums: missing basename was accepted]"; FAIL=$((FAIL + 1))
else
    echo "  PASS [verify_in_sums: missing basename rejected]"; PASS=$((PASS + 1))
fi

# (d) Does NOT false-match the regex-coincidence decoy. SHA256SUMS lists ONLY the
# decoy (with a VALID hash for the existing decoy file), and the real basename is
# absent. The old `grep -E` selector matched the decoy line and would `-c` the
# decoy file -> a FALSE PASS; the awk exact match must reject (no entry for the
# real basename). This is the case that catches the B2 regex selector.
printf '%s  %s\n' "$SVIS_DECOY_SHA" "$SVIS_DECOY" > "$svis_dir/SHA256SUMS"
if ( cd "$svis_dir" && sha256_verify_in_sums "$SVIS_NAME" SHA256SUMS ) >/dev/null 2>&1; then
    echo "  FAIL [verify_in_sums: false-matched a regex-coincidence decoy]"; FAIL=$((FAIL + 1))
else
    echo "  PASS [verify_in_sums: no false-match against regex-coincidence decoy]"; PASS=$((PASS + 1))
fi

rm -rf "$svis_dir"

echo "hash helper: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
