#!/usr/bin/env sh
# Tests for the LLM-broker launcher behaviour (feature 0064 §30): the broker is
# the DEFAULT whenever LLM is enabled, for EVERY provider (native Gemini +
# Anthropic adapters included); --no-broker opts out; skills = no LLM = no
# broker. Uses VULTURE_LAUNCH_DRY_RUN=1 so start.sh / prod_start.sh resolve
# config and exit before booting anything (and skip provider liveness pings).
#
# POSIX sh; the launchers are bash and invoked with bash explicitly.
# Run: scripts/tests/test_broker_flags.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START="$SCRIPT_DIR/../start.sh"
PROD="$SCRIPT_DIR/../prod_start.sh"
PASS=0
FAIL=0

run_dev() {
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null \
        OPENAI_API_KEY=dummy ANTHROPIC_API_KEY=dummy GEMINI_API_KEY=dummy \
        bash "$START" "$@" 2>&1
}
run_server() {
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null \
        VULTURE_DB_PASSWORD=pw OPENAI_API_KEY=dummy ANTHROPIC_API_KEY=dummy GEMINI_API_KEY=dummy \
        bash "$PROD" "$@" 2>&1
}

assert_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [$label] — expected: $needle"
        echo "    output: $haystack"; FAIL=$((FAIL + 1))
    fi
}
assert_not_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  FAIL [$label] — did NOT expect: $needle"
        echo "    output: $haystack"; FAIL=$((FAIL + 1))
    else
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    fi
}

echo "test_broker_flags:"

# ── Default-on (§30): LLM enabled ⇒ broker on WITHOUT any flag ─────────────
out=$(run_dev lmstudio my-model)
assert_contains "$out" "Broker:    on" "dev lmstudio: broker ON by default (no flag)"
assert_contains "$out" "openai-compatible" "dev lmstudio: openai-compatible provider"
assert_contains "$out" "local-egress: on" "dev lmstudio: local egress on"

# --no-broker opts out.
out=$(run_dev lmstudio my-model --no-broker)
assert_not_contains "$out" "Broker:    on" "dev lmstudio --no-broker: broker OFF"

# skills = no LLM = no broker.
out=$(run_dev skills)
assert_not_contains "$out" "Broker:    on" "dev skills: no LLM ⇒ no broker"

# ── Every provider is brokerable (native adapters) ────────────────────────
out=$(run_dev openai gpt-4o)
assert_contains "$out" "Broker provider:     openai" "dev openai: provider openai"

out=$(run_dev ollama my-model)
assert_contains "$out" "11434/v1" "dev ollama: egress at ollama /v1"

# gemini → native gemini adapter (no OpenAI-wire rejection any more).
out=$(run_dev gemini gemini-2.5-flash)
assert_contains "$out" "Broker provider:     gemini" "dev gemini: native gemini adapter"
assert_not_contains "$out" "OpenAI-wire" "dev gemini: NOT rejected"

# anthropic → native anthropic adapter.
out=$(run_dev anthropic claude-3-5-sonnet)
assert_contains "$out" "Broker provider:     anthropic" "dev anthropic: native anthropic adapter"
assert_not_contains "$out" "OpenAI-wire" "dev anthropic: NOT rejected"

# --budget still surfaces the cap.
out=$(run_dev openai gpt-4o --budget 25)
assert_contains "$out" "25" "dev: budget cap surfaced"

# ── Mode B (prod_start.sh) ────────────────────────────────────────────────
out=$(run_server openai gpt-4o)
assert_contains "$out" "Broker:    on" "server openai: broker ON by default"
assert_contains "$out" "key isolation" "server openai: key-isolation note"

out=$(run_server gemini gemini-2.5-flash)
assert_contains "$out" "Broker provider:     gemini" "server gemini: native gemini adapter"

out=$(run_server anthropic claude-3-5-sonnet --no-broker)
assert_not_contains "$out" "Broker:    on" "server anthropic --no-broker: broker OFF"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
