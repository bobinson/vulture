#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Read port from config.ini with fallback
ini_get() {
    local section="$1" key="$2" fallback="${3:-}"
    local val
    val=$(awk -v sec="[$section]" -v k="$key" '
        /^\[/ { in_sec = ($0 == sec) }
        in_sec && match($0, "^[[:space:]]*"k"[[:space:]]*=") {
            sub(/^[^=]*=[[:space:]]*/, ""); print; exit
        }
    ' "$PROJECT_ROOT/config.ini" 2>/dev/null)
    echo "${val:-$fallback}"
}

# Service name → port, all driven from config.ini
declare -a SERVICES=(
    "backend:$(ini_get ports backend 28080)"
    "agent-chaos:$(ini_get ports agent_chaos 28001)"
    "agent-owasp:$(ini_get ports agent_owasp 28002)"
    "agent-soc2:$(ini_get ports agent_soc2 28003)"
    "agent-cwe:$(ini_get ports agent_cwe 28004)"
    "agent-prove:$(ini_get ports agent_prove 28005)"
    "agent-xss:$(ini_get ports agent_xss 28006)"
    "agent-ssdf:$(ini_get ports agent_ssdf 28007)"
    "agent-discover:$(ini_get ports agent_discover 28008)"
    "agent-do178c:$(ini_get ports agent_do178c 28009)"
    "agent-asvs:$(ini_get ports agent_asvs 28010)"
    "frontend:$(ini_get ports frontend_host 23001)"
)

find_pids_on_port() {
    lsof -ti ":$1" 2>/dev/null || true
}

is_port_open() {
    timeout 0.5 bash -c "echo >/dev/tcp/localhost/$1" 2>/dev/null
}

echo
echo "  Stopping Vulture services..."
echo

stopped=0

for entry in "${SERVICES[@]}"; do
    name="${entry%%:*}"
    port="${entry##*:}"

    pids=$(find_pids_on_port "$port")
    [[ -z "$pids" ]] && continue

    for pid in $pids; do
        if kill -TERM "$pid" 2>/dev/null; then
            printf "  Stopped %-15s (pid %s, port %s)\n" "$name" "$pid" "$port"
            stopped=$((stopped + 1))
        else
            echo "  warning: kill $name (pid $pid): failed" >&2
        fi
    done
done

if [[ $stopped -eq 0 ]]; then
    echo "  No running Vulture services found."
    exit 0
fi

# Wait briefly for processes to exit
sleep 0.5

# Verify ports are free, SIGKILL stragglers
remaining=0
for entry in "${SERVICES[@]}"; do
    port="${entry##*:}"
    if is_port_open "$port"; then
        remaining=$((remaining + 1))
    fi
done

if [[ $remaining -gt 0 ]]; then
    echo
    echo "  $remaining service(s) still shutting down, sending SIGKILL..."
    for entry in "${SERVICES[@]}"; do
        port="${entry##*:}"
        pids=$(find_pids_on_port "$port")
        for pid in $pids; do
            kill -KILL "$pid" 2>/dev/null || true
        done
    done
fi

echo
echo "  $stopped service(s) stopped."
echo
