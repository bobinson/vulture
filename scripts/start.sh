#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
ENV_FILE="$PROJECT_ROOT/.env"

usage() {
    cat <<'EOF'
Usage: scripts/start.sh <provider> [model]

Providers:
  openai [model]       OpenAI API (default: gpt-4o)
  anthropic [model]    Anthropic API (default: claude-sonnet)
  ollama [model]       Local Ollama (default: qwen3:1.7b)
  lmstudio [model]     LM Studio (default: local-model)
  skills               Skills only — no LLM (fastest, no API key needed)

Examples:
  scripts/start.sh openai
  scripts/start.sh openai gpt-4o
  scripts/start.sh anthropic claude-sonnet
  scripts/start.sh ollama qwen3:8b
  scripts/start.sh lmstudio my-model
  scripts/start.sh skills
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
    if ! command -v ollama &>/dev/null; then
        echo "Error: ollama not found. Install from https://ollama.com"
        exit 1
    fi
    if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
        echo "Error: Ollama not running. Start it with: ollama serve"
        exit 1
    fi
}

check_lmstudio() {
    local url="${OPENAI_BASE_URL:-http://localhost:1234/v1}"
    if ! curl -sf "$url/models" &>/dev/null; then
        echo "Error: LM Studio not reachable at $url"
        echo "  Start LM Studio and enable the local server."
        exit 1
    fi
}

build_backend() {
    local bin="$BACKEND_DIR/vulture"
    if [[ ! -x "$bin" ]] || [[ "$BACKEND_DIR/cmd/vulture/main.go" -nt "$bin" ]]; then
        echo "  Building backend..."
        (cd "$BACKEND_DIR" && go build -o vulture ./cmd/vulture/)
    fi
}

# --- Main ---

[[ $# -lt 1 ]] && usage

PROVIDER="$1"
MODEL="${2:-}"

load_env
export PATH="/home/user/go/bin:$PATH"

echo
echo "  Vulture — starting with provider: $PROVIDER"
echo

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
        # Ollama auto-detected by launcher; ensure host is set
        export OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
        ;;

    lmstudio)
        MODEL="${MODEL:-local-model}"
        export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:1234/v1}"
        export OPENAI_API_KEY="${OPENAI_API_KEY:-lm-studio}"
        check_lmstudio
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
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

build_backend
exec "$BACKEND_DIR/vulture" local_start
