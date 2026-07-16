#!/usr/bin/env sh
# Tests that docker-compose.yml wires the LLM broker (feature 0064): broker env
# reaches the backend + agents, and in broker mode the provider API key reaches
# ONLY the backend (N1 key isolation), never the agent containers.
#
# Renders the compose file with `docker compose config` (interpolates env) and
# asserts on the resolved output. Skipped (pass) where docker compose is absent.
#
# Run: scripts/tests/test_broker_compose.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE="$ROOT/docker-compose.yml"
PASS=0
FAIL=0

echo "test_broker_compose:"

if ! docker compose version >/dev/null 2>&1; then
    echo "  SKIP — 'docker compose' not available"
    exit 0
fi

render() {
    # $@ = extra "KEY=VAL" env assignments for interpolation. Exported inside a
    # subshell (leading "$@" words are NOT recognized as assignments post-
    # expansion), inheriting the ambient env so the docker CLI keeps its socket.
    (
        export VULTURE_DB_PASSWORD=pw
        # shellcheck disable=SC2163  # "$kv" is a KEY=VAL word — export applies it correctly
        for kv in "$@"; do export "$kv"; done
        docker compose -f "$COMPOSE" config 2>/dev/null
    )
}

assert() {
    cond="$1"; label="$2"
    if [ "$cond" -eq 0 ] 2>/dev/null; then
        echo "  FAIL [$label]"; FAIL=$((FAIL + 1))
    else
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    fi
}

# ── Broker ON: key isolation ──────────────────────────────────────────────
# Backend holds the key; agents get the key var emptied (VULTURE_AGENT_OPENAI_API_KEY="").
broker_on=$(render \
    VULTURE_LLM_BROKER=on \
    VULTURE_LLM_BROKER_URL=http://backend:8090/v1 \
    OPENAI_API_KEY=secret-key-xyz \
    VULTURE_AGENT_OPENAI_API_KEY=)

# The real key must appear EXACTLY once (backend only) across all 11 services.
key_count=$(printf '%s' "$broker_on" | grep -c 'secret-key-xyz')
[ "$key_count" = "1" ] && iso=1 || iso=0
assert "$iso" "broker on: provider key reaches backend ONLY (found $key_count, want 1)"

# Broker env is wired for the agents.
printf '%s' "$broker_on" | grep -q 'backend:8090/v1' && u=1 || u=0
assert "$u" "broker on: VULTURE_LLM_BROKER_URL wired to agents"

printf '%s' "$broker_on" | grep -qE 'VULTURE_LLM_BROKER: *.?on' && bo=1 || bo=0
assert "$bo" "broker on: VULTURE_LLM_BROKER=on rendered"

# ── Broker OFF (default): behaviour unchanged ─────────────────────────────
# Without broker vars the key still reaches backend + all 10 agents (11 total).
broker_off=$(render OPENAI_API_KEY=secret-key-xyz)
off_count=$(printf '%s' "$broker_off" | grep -c 'secret-key-xyz')
[ "$off_count" -ge 11 ] && back=1 || back=0
assert "$back" "broker off (default): key reaches backend + all agents (found $off_count, want >=11)"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
