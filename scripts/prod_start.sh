#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

usage() {
    cat <<'EOF'
Usage: scripts/prod_start.sh <provider> [model]

Providers:
  openai [model]       OpenAI API (default: gpt-4o)
  anthropic [model]    Anthropic API (default: claude-sonnet)
  ollama [model]       Local Ollama (default: qwen3:1.7b)
  lmstudio [model]     LM Studio (default: local-model)
  skills               Skills only — no LLM (fastest, no API key needed)

Examples:
  scripts/prod_start.sh openai
  scripts/prod_start.sh openai gpt-4o
  scripts/prod_start.sh anthropic claude-sonnet
  scripts/prod_start.sh ollama qwen3:8b
  scripts/prod_start.sh lmstudio my-model
  scripts/prod_start.sh skills
EOF
    exit 1
}

load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "$ENV_FILE"
        set +a
    fi
}

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

require_key() {
    local var="$1" name="$2"
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var not set. Add it to $ENV_FILE or export it."
        echo "  export $var=your-key-here"
        exit 1
    fi
    echo "  $name key: ${!var:0:8}...${!var: -4}"
}

check_ollama() {
    local url="${OLLAMA_DEFAULT_URL:-http://localhost:11434}"
    if ! curl -sf "$url/api/tags" &>/dev/null; then
        echo "Error: Ollama not reachable at $url"
        echo "  Start it with: ollama serve"
        exit 1
    fi
}

check_lmstudio() {
    local url="${OPENAI_BASE_URL:-$LMSTUDIO_DEFAULT_URL}"
    if ! curl -sf "$url/models" &>/dev/null; then
        echo "Error: LM Studio not reachable at $url"
        echo "  Start LM Studio and enable the local server."
        exit 1
    fi
}

detect_lmstudio_model() {
    local url="${OPENAI_BASE_URL:-$LMSTUDIO_DEFAULT_URL}"
    local first
    first=$(curl -sf "$url/models" 2>/dev/null \
        | python3 -c "import sys,json; models=[m['id'] for m in json.load(sys.stdin)['data'] if 'embed' not in m['id'].lower()]; print(models[0] if models else '')" 2>/dev/null)
    echo "${first:-local-model}"
}

check_docker() {
    if ! command -v docker &>/dev/null; then
        echo "Error: docker not found. Install Docker from https://docs.docker.com/get-docker/"
        exit 1
    fi
    if ! docker compose version &>/dev/null; then
        echo "Error: 'docker compose' not available. Install Docker Compose v2."
        exit 1
    fi
}

wait_for_health() {
    local url="$1" timeout_secs="$2"
    local elapsed=0
    printf "  Waiting for backend health"
    while [[ $elapsed -lt $timeout_secs ]]; do
        if curl -sf "$url" &>/dev/null; then
            printf " ready (%ds)\n" "$elapsed"
            return 0
        fi
        printf "."
        sleep 2
        elapsed=$((elapsed + 2))
    done
    printf " TIMEOUT after %ds\n" "$timeout_secs"
    echo "  Warning: backend did not become healthy within ${timeout_secs}s."
    echo "  Check logs with: docker compose logs backend"
    return 1
}

# --- Main ---

[[ $# -lt 1 || "${1:-}" == "--help" || "${1:-}" == "-h" ]] && usage

PROVIDER="$1"
MODEL="${2:-}"

load_env

# Read defaults from config.ini
OLLAMA_DEFAULT_URL=$(ini_get ollama url "http://localhost:11434")
LMSTUDIO_DEFAULT_URL=$(ini_get lmstudio url "http://localhost:1234/v1")
BACKEND_PORT=$(ini_get ports backend "28080")
FRONTEND_PORT=$(ini_get ports frontend_host "23001")
POSTGRES_PORT=$(ini_get ports postgres_host "25433")

echo
echo "  Vulture Production — starting with provider: $PROVIDER"
echo

# Prereq checks
check_docker

# Provider-specific setup
case "$PROVIDER" in
    openai)
        MODEL="${MODEL:-gpt-4o}"
        require_key OPENAI_API_KEY "OpenAI"
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
        ;;

    anthropic)
        MODEL="${MODEL:-claude-sonnet}"
        require_key ANTHROPIC_API_KEY "Anthropic"
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
        ;;

    ollama)
        MODEL="${MODEL:-qwen3:1.7b}"
        check_ollama
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
        # Containers reach host Ollama via host.docker.internal
        export OLLAMA_API_BASE="http://host.docker.internal:11434"
        ;;

    lmstudio)
        # Always check against localhost (not a previous host.docker.internal from .env)
        local_lmstudio_url="$LMSTUDIO_DEFAULT_URL"
        export OPENAI_BASE_URL="$local_lmstudio_url"
        export OPENAI_API_KEY="${OPENAI_API_KEY:-lm-studio}"
        check_lmstudio
        if [[ -z "$MODEL" ]]; then
            MODEL=$(detect_lmstudio_model)
            echo "  Auto-detected model: $MODEL"
        fi
        # LiteLLM needs openai/ prefix for OpenAI-compatible endpoints
        if [[ "$MODEL" != openai/* ]]; then
            MODEL="openai/$MODEL"
        fi
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
        # Rewrite base URL for container access
        export OPENAI_BASE_URL="http://host.docker.internal:1234/v1"
        ;;

    skills|none)
        MODEL="(none)"
        export VULTURE_USE_LLM=false
        unset VULTURE_LLM_MODEL 2>/dev/null || true
        ;;

    *)
        echo "Error: unknown provider '$PROVIDER'"
        echo
        usage
        ;;
esac

echo "  Provider:  $PROVIDER"
echo "  Model:     $MODEL"
echo "  LLM:       ${VULTURE_USE_LLM:-false}"
echo

# Generate .env from config.ini
echo "  Generating .env..."
"$SCRIPT_DIR/gen-env.sh"

# Append LLM-specific vars to .env
{
    echo ""
    echo "# LLM provider (set by prod_start.sh)"
    echo "VULTURE_USE_LLM=${VULTURE_USE_LLM:-false}"
    [[ -n "${VULTURE_LLM_MODEL:-}" ]] && echo "VULTURE_LLM_MODEL=$VULTURE_LLM_MODEL"
    [[ -n "${OPENAI_API_KEY:-}" ]] && echo "OPENAI_API_KEY=$OPENAI_API_KEY"
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] && echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
    [[ -n "${OPENAI_BASE_URL:-}" ]] && echo "OPENAI_BASE_URL=$OPENAI_BASE_URL"
    [[ -n "${OLLAMA_API_BASE:-}" ]] && echo "OLLAMA_API_BASE=$OLLAMA_API_BASE"
} >> "$ENV_FILE"

# Build shared agent base image (once, reused by all 7 agents)
echo "  Building agent base image..."
docker build -t vulture-agent-base:latest -f "$PROJECT_ROOT/agents/Dockerfile.base" "$PROJECT_ROOT/agents/" -q

# Launch docker compose
echo "  Starting docker compose..."
echo
docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d --build

echo

# Wait for backend health
wait_for_health "http://localhost:$BACKEND_PORT/health" 60 || true

echo
echo "  ──────────────────────────────────────────"
echo "  Vulture Production is running"
echo ""
echo "  Frontend:   http://localhost:$FRONTEND_PORT"
echo "  Backend:    http://localhost:$BACKEND_PORT"
echo "  PostgreSQL: localhost:$POSTGRES_PORT"
echo ""
echo "  Provider:   $PROVIDER"
echo "  Model:      $MODEL"
echo ""
echo "  Logs:       docker compose logs -f"
echo "  Stop:       scripts/prod_stop.sh"
echo "  ──────────────────────────────────────────"
echo
