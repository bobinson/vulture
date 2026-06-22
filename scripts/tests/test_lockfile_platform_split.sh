#!/usr/bin/env sh
#
# RED-phase test for the macOS cryptography wheel gap (LLD 0055 B1a).
#
# `cryptography` 49.x dropped the macOS x86_64 (Intel) wheel — arm64-only — so a
# single universal pin can't `pip install --only-binary :all:` on the darwin/amd64
# release leg (macos-15-intel). The fix is a marker-SPLIT pin in the one universal
# lockfile: Darwin caps to the newest release that still ships a macosx universal2
# wheel; everything else tracks latest. The split is reproducible from a committed
# `uv --constraint` file, never hand-edited.
#
# These are STATIC assertions over the committed lockfile + generator. Against the
# pristine (single-pin) tree they FAIL (expected RED): the lockfile carries one
# unconditional `cryptography==<v>` line, no constraint file exists, and
# gen-lockfile.sh passes no `--constraint`. This test only asserts the desired
# contract; it does not implement the fix.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final tally, exit 1 on any FAIL. No bashisms.

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
LOCK="$REPO_ROOT/agents/requirements-frozen.txt"
CONSTRAINT="$REPO_ROOT/agents/lockfile-constraints.txt"
GEN="$REPO_ROOT/scripts/gen-lockfile.sh"

require_file_or_bail "lockfile-present" "$LOCK"
require_file_or_bail "gen-lockfile-present" "$GEN"

# Marker shapes uv emits (single-quoted value, single-spaced). Use '.' for the
# quote chars so a quoting/spacing nuance can't make the test brittle.
DARWIN_PIN="^cryptography==[0-9][0-9.]* ; sys_platform == .darwin."
OTHER_PIN="^cryptography==[0-9][0-9.]* ; sys_platform != .darwin."

# ---------------------------------------------------------------------------
# TEST 1 — Darwin gets its own cryptography pin (the leg that lacks an Intel wheel).
# ---------------------------------------------------------------------------
assert_file_matches \
    "lockfile-has-darwin-cryptography-pin" \
    "$LOCK" \
    "$DARWIN_PIN" \
    "no Darwin-gated cryptography pin — the darwin/amd64 build can't install a 49.x arm64-only wheel"

# ---------------------------------------------------------------------------
# TEST 2 — non-Darwin keeps its own (newer) cryptography pin.
# ---------------------------------------------------------------------------
assert_file_matches \
    "lockfile-has-non-darwin-cryptography-pin" \
    "$LOCK" \
    "$OTHER_PIN" \
    "no non-Darwin cryptography pin — the universal lockfile didn't fork cryptography on a platform marker"

# ---------------------------------------------------------------------------
# TEST 3 — the two pins are DIFFERENT versions (a real split, not two equal pins).
# ---------------------------------------------------------------------------
crypto_ver() { # <op>  ('==' Darwin | '!=' non-Darwin)
    grep -E "^cryptography==[0-9][0-9.]* ; sys_platform $1 .darwin." "$LOCK" \
        | sed -E 's/^cryptography==([0-9][0-9.]*) .*/\1/' | head -n1
}
test_versions_differ() {
    name="darwin-cryptography-pin-differs-from-non-darwin"
    d=$(crypto_ver '=='); o=$(crypto_ver '!=')
    if [ -n "$d" ] && [ -n "$o" ] && [ "$d" != "$o" ]; then
        pass "$name"
    else
        fail "$name" "expected distinct Darwin vs non-Darwin cryptography pins (got darwin='$d' other='$o')"
    fi
}
test_versions_differ

# ---------------------------------------------------------------------------
# TEST 4 — the Darwin pin is hash-pinned (the line is immediately followed by a
# --hash continuation, like every other --generate-hashes entry).
# ---------------------------------------------------------------------------
test_darwin_pin_hashed() {
    name="darwin-cryptography-pin-is-hash-pinned"
    if awk '
        prev ~ /^cryptography==[0-9][0-9.]* ; sys_platform == .darwin./ && /--hash=sha256:/ { found=1 }
        { prev=$0 }
        END { exit !found }
    ' "$LOCK"; then
        pass "$name"
    else
        fail "$name" "the Darwin cryptography pin is not followed by a --hash= line (not hash-pinned)"
    fi
}
test_darwin_pin_hashed

# ---------------------------------------------------------------------------
# TEST 5 — the split is REPRODUCIBLE, not hand-edited: a committed constraint file
# carries a Darwin-gated cryptography pin.
# ---------------------------------------------------------------------------
require_file_or_bail "constraint-file-present" "$CONSTRAINT"
assert_file_matches \
    "constraint-pins-cryptography-on-darwin" \
    "$CONSTRAINT" \
    "cryptography==[0-9][0-9.]*; *sys_platform == .darwin." \
    "lockfile-constraints.txt does not pin cryptography on Darwin (the split would not survive 'make freeze-deps')"

# ---------------------------------------------------------------------------
# TEST 6 — the generator WIRES the constraint, so check-lockfile.sh (which calls
# gen-lockfile.sh) reproduces the same split and stays green.
# ---------------------------------------------------------------------------
assert_file_matches \
    "gen-lockfile-wires-constraint" \
    "$GEN" \
    '\-\-constraint' \
    "gen-lockfile.sh passes no --constraint; the platform split would not be regenerated"

# ---------------------------------------------------------------------------
finish
