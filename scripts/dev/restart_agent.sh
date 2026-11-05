#!/usr/bin/env bash
# dev/restart_agent.sh — surgically restart ONE Vulture agent without touching the rest
# of the stack (backend, Postgres, the other agents).
#
# Use it when:
#   - you edited an agent's Python and need the running uvicorn to reload the code
#     (the dev stack import-caches code at start — a "stale worker" serves old code);
#   - you want to change one agent's env (e.g. enable the L5 judge / raise token caps)
#     without a full `scripts/vulture.sh` restart.
#
# Usage:
#   scripts/dev/restart_agent.sh <agent> <port> [VAR=VAL ...]
#
# Examples:
#   scripts/dev/restart_agent.sh cwe 28004
#   scripts/dev/restart_agent.sh cwe 28004 VULTURE_USE_VALIDATE_LLM=true VULTURE_VALIDATE_LLM_MAX_TOKENS=16000
#
# Env:
#   VULTURE_RUNTIME_DIR   runtime root the dev stack runs agents from
#                         (default: $HOME/.vulture/runtime)
#
# Agent→port map (dev `scripts/vulture.sh dev` defaults): chaos 28001, owasp 28002,
# soc2 28003, cwe 28004, prove 28005, xss 28006, ssdf 28007, discover 28008,
# do178c 28009, asvs 28010.
set -u

AGENT="${1:?usage: restart_agent.sh <agent> <port> [VAR=VAL ...]}"
PORT="${2:?usage: restart_agent.sh <agent> <port> [VAR=VAL ...]}"
shift 2 || true

RUNTIME="${VULTURE_RUNTIME_DIR:-$HOME/.vulture/runtime}"
APP="${AGENT}_agent.main:app"
AGENT_DIR="$RUNTIME/agents/$AGENT"
PYBIN="$RUNTIME/python/bin/python3.12"
LOG="$(mktemp -t "vulture-${AGENT}-XXXXXX.log")"

[ -d "$AGENT_DIR" ] || { echo "error: agent dir not found: $AGENT_DIR (set VULTURE_RUNTIME_DIR)"; exit 3; }
[ -x "$PYBIN" ] || PYBIN="python3"

# Only the agent on THIS port — another stack may run the same module elsewhere.
MATCH="uvicorn $APP .*--port $PORT\$"

# agent_token_of <pid> — the VULTURE_AGENT_TOKEN a running agent was started
# with (/proc on Linux, `ps -E` on macOS). The launcher generates one per start;
# the restarted agent must keep it to accept the backend's calls and to keep
# refusing everyone else's.
agent_token_of() {
    if [ -r "/proc/$1/environ" ]; then
        tr '\0' '\n' < "/proc/$1/environ" | sed -n 's/^VULTURE_AGENT_TOKEN=//p'
    else
        ps -E -ww -o command= -p "$1" 2>/dev/null | tr ' ' '\n' | sed -n 's/^VULTURE_AGENT_TOKEN=//p'
    fi
}
if [ -z "${VULTURE_AGENT_TOKEN:-}" ]; then
    for pid in $(pgrep -f "$MATCH" 2>/dev/null); do
        tok=$(agent_token_of "$pid")
        if [ -n "$tok" ]; then export VULTURE_AGENT_TOKEN="$tok"; break; fi
    done
fi

echo "[restart] stopping '$APP' on :$PORT ..."
for pid in $(pgrep -f "$MATCH" 2>/dev/null); do
    echo "  SIGTERM $pid"; kill -TERM "$pid" 2>/dev/null || true
done
for _ in $(seq 1 20); do
    curl -s -o /dev/null --max-time 1 "http://localhost:$PORT/health" 2>/dev/null || { echo "  :$PORT down"; break; }
    sleep 0.5
done
for pid in $(pgrep -f "$MATCH" 2>/dev/null); do
    echo "  SIGKILL leftover $pid"; kill -9 "$pid" 2>/dev/null || true
done
sleep 1

# Apply any VAR=VAL overrides passed as trailing args (inherited by the new process).
for kv in "$@"; do export "$kv"; done

echo "[restart] starting '$APP' from $AGENT_DIR (log: $LOG) ..."
( cd "$AGENT_DIR" && nohup "$PYBIN" -m uvicorn "$APP" --host 127.0.0.1 --port "$PORT" >"$LOG" 2>&1 &
  echo "  PID=$!" )

for i in $(seq 1 60); do
    if curl -s -o /dev/null --max-time 1 "http://localhost:$PORT/health" 2>/dev/null; then
        echo "[restart] '$AGENT' healthy after $(awk "BEGIN{print $i*0.5}")s"; exit 0
    fi
    sleep 0.5
done
echo "[restart] WARN: '$AGENT' not healthy in 30s; tail $LOG:"
tail -n 20 "$LOG"
exit 1
