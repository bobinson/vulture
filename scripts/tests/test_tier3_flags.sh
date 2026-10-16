#!/usr/bin/env sh
# Tests for the --tier3 / --deep launcher flag. Uses VULTURE_LAUNCH_DRY_RUN=1
# so start.sh / prod_start.sh resolve config and exit before booting anything.
#
#   * The tier-3 state is printed only when the LLM phase is actually enabled
#     (after provider resolution); with the skills provider the flag has no
#     effect and the launcher says so instead of announcing "ON".
#   * The help text does not claim the flag reaches "all files": the sweep is
#     still bounded by VULTURE_LLM_MAX_FILES, the budget and the prose limits.
#   * `vulture.sh server ... --tier3` (prod_start.sh) understands the flag
#     instead of taking it as the model name, writes it to the generated .env,
#     and an unknown option is rejected rather than used as a model.
#   * docker-compose.yml forwards VULTURE_LLM_TIER3 to every agent that is
#     forwarded the other VULTURE_LLM_* settings.
#
# POSIX sh; the launchers are bash and invoked with bash explicitly.
# Run: scripts/tests/test_tier3_flags.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START="$SCRIPT_DIR/../start.sh"
PROD="$SCRIPT_DIR/../prod_start.sh"
COMPOSE="$SCRIPT_DIR/../../docker-compose.yml"
PASS=0
FAIL=0

run_dev() {
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null VULTURE_LLM_TIER3='' \
        OPENAI_API_KEY=dummy bash "$START" "$@" 2>&1
}
run_server() {
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null VULTURE_LLM_TIER3='' \
        VULTURE_DB_PASSWORD=pw OPENAI_API_KEY=dummy bash "$PROD" "$@" 2>&1
}

assert_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [$label] — expected: $needle"
        echo "    output: $haystack"; FAIL=$((FAIL + 1))
    fi
}
assert_not_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        echo "  FAIL [$label] — did NOT expect: $needle"
        echo "    output: $haystack"; FAIL=$((FAIL + 1))
    else
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    fi
}
assert_equal() {
    got="$1"; want="$2"; label="$3"
    if [ "$got" = "$want" ]; then
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [$label] — got '$got', want '$want'"; FAIL=$((FAIL + 1))
    fi
}

echo "test_tier3_flags:"

# ── Mode A (start.sh) ─────────────────────────────────────────────────────
out=$(run_dev skills --tier3)
assert_not_contains "$out" "Tier-3:" "dev skills --tier3: no tier-3 state without an LLM"
assert_not_contains "$out" "ON (full-file-coverage" "dev skills --tier3: no overclaiming ON line"
assert_contains "$out" "--tier3 has no effect" "dev skills --tier3: says the flag is ignored"

out=$(run_dev openai gpt-4o --tier3)
assert_contains "$out" "Tier-3:    on" "dev openai --tier3: tier-3 on"
assert_contains "$out" "Model:     gpt-4o" "dev openai --tier3: flag is not the model"

out=$(run_dev openai gpt-4o --deep)
assert_contains "$out" "Tier-3:    on" "dev openai --deep: alias"

out=$(run_dev openai gpt-4o)
assert_contains "$out" "Tier-3:    off" "dev openai: tier-3 state shown when the LLM is on"

out=$(VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null bash "$START" 2>&1 || true)
assert_not_contains "$out" "all files" "dev help: no 'all files' claim"
assert_contains "$out" "VULTURE_LLM_MAX_FILES" "dev help: names the cap that still applies"

# ── Mode B (prod_start.sh) ────────────────────────────────────────────────
out=$(run_server openai gpt-4o --tier3)
assert_contains "$out" "Model:     gpt-4o" "server openai --tier3: flag is not the model"
assert_contains "$out" "Tier-3:    on" "server openai --tier3: tier-3 on"

out=$(run_server openai --tier3)
assert_contains "$out" "Model:     gpt-4o" "server openai --tier3 (no model): default model, not the flag"

out=$(run_server skills --tier3)
assert_contains "$out" "--tier3 has no effect" "server skills --tier3: says the flag is ignored"

out=$(run_server openai --bogus-flag)
assert_contains "$out" "unknown option '--bogus-flag'" "server: an unknown option is rejected"
assert_not_contains "$out" "Model:     --bogus-flag" "server: an unknown option is never the model"

# A previous `server ... --tier3` leaves VULTURE_LLM_TIER3=true in the
# generated .env, which load_env sources: a later launch without the flag must
# not inherit it.
prev_env=$(mktemp)
printf 'VULTURE_LLM_TIER3=true\n' > "$prev_env"
out=$(VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE="$prev_env" VULTURE_LLM_TIER3='' \
    VULTURE_DB_PASSWORD=pw OPENAI_API_KEY=dummy bash "$PROD" openai gpt-4o 2>&1)
rm -f "$prev_env"
assert_contains "$out" "Tier-3:    off" "server: a previous run's --tier3 does not stick"

out=$(VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null VULTURE_LLM_TIER3=true \
    VULTURE_DB_PASSWORD=pw OPENAI_API_KEY=dummy bash "$PROD" openai gpt-4o 2>&1)
assert_contains "$out" "Tier-3:    on" "server: tier-3 from the real environment is kept"

# shellcheck disable=SC2016  # the literal compose/.env text is the subject
if grep -q 'VULTURE_LLM_TIER3=${VULTURE_LLM_TIER3}' "$PROD"; then
    echo "  PASS [server: tier-3 written to the generated .env]"; PASS=$((PASS + 1))
else
    echo "  FAIL [server: tier-3 written to the generated .env]"; FAIL=$((FAIL + 1))
fi

# ── docker-compose.yml ────────────────────────────────────────────────────
agents=$(grep -c '^  agent-[a-z0-9]*:$' "$COMPOSE")
# shellcheck disable=SC2016  # the literal compose/.env text is the subject
tier3_agents=$(grep -c 'VULTURE_LLM_TIER3=${VULTURE_LLM_TIER3:-}' "$COMPOSE")
assert_equal "$tier3_agents" "$agents" "compose: tier-3 forwarded to every agent service"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
