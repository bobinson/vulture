#!/usr/bin/env bash
# Tests for the --embed-url / --embed-model launcher flags (NVIDIA +
# local-embeddings split). Uses VULTURE_LAUNCH_DRY_RUN=1 so start.sh
# resolves config and exits before booting the backend.
#
# Run: scripts/tests/test_embed_flags.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START="$SCRIPT_DIR/../start.sh"
PASS=0
FAIL=0

run_dry() {
    # $@ = args to start.sh; prints its stdout+stderr
    VULTURE_LAUNCH_DRY_RUN=1 bash "$START" "$@" 2>&1
}

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  PASS [$label]"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$label] — expected to find: $needle"
        echo "    output: $haystack"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  FAIL [$label] — did NOT expect: $needle"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS [$label]"
        PASS=$((PASS + 1))
    fi
}

echo "test_embed_flags:"

# 1. --embed-url + --embed-model (space form) are surfaced in dry-run.
out=$(run_dry skills --embed-url http://localhost:1234/v1 --embed-model my-embed-model)
assert_contains "$out" "http://localhost:1234/v1" "space form: embed url"
assert_contains "$out" "my-embed-model" "space form: embed model"

# 2. --embed-url=... (equals form) also works.
out=$(run_dry skills --embed-url=http://127.0.0.1:1234/v1 --embed-model=eq-model)
assert_contains "$out" "http://127.0.0.1:1234/v1" "equals form: embed url"
assert_contains "$out" "eq-model" "equals form: embed model"

# 3. The provider+model positionals still parse with flags interleaved.
#    openai provider requires a key before reaching the summary line, so
#    supply a dummy one — we're exercising arg parsing, not auth.
out=$(OPENAI_API_KEY=dummy-key-for-argparse-test run_dry openai z-ai/glm-5.1 --embed-url http://localhost:1234/v1 --embed-model e)
assert_contains "$out" "z-ai/glm-5.1" "positional model preserved alongside flags"
assert_contains "$out" "openai" "provider preserved alongside flags"

# 4. Without the flags, no embed override is printed.
out=$(run_dry skills)
assert_not_contains "$out" "Embed URL:" "no flags → no embed override line"

# 5. Missing value is an error.
out=$(run_dry skills --embed-url 2>&1 || true)
assert_contains "$out" "needs a value" "missing --embed-url value errors"

echo
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
