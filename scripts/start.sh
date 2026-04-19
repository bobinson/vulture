#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
ENV_FILE="$PROJECT_ROOT/.env"

# Ensure pyenv shims are on PATH when running non-interactively.
if [[ -d "$HOME/.pyenv/shims" ]] && [[ ":$PATH:" != *":$HOME/.pyenv/shims:"* ]]; then
    export PATH="$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH"
fi

usage() {
    cat <<'EOF'
Usage: scripts/vulture.sh dev <provider> [model]

Providers:
  openai [model]       OpenAI API (default: gpt-4o)
  anthropic [model]    Anthropic API (default: claude-sonnet)
  ollama [model]       Local Ollama (default: qwen3:1.7b)
  lmstudio [model]     LM Studio (default: local-model)
  skills               Skills only — no LLM (fastest, no API key needed)

Examples:
  scripts/vulture.sh dev openai
  scripts/vulture.sh dev openai gpt-4o
  scripts/vulture.sh dev anthropic claude-sonnet
  scripts/vulture.sh dev ollama qwen3:8b
  scripts/vulture.sh dev lmstudio my-model
  scripts/vulture.sh dev skills
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
    if ! curl -sf "${OLLAMA_DEFAULT_URL:-http://localhost:11434}/api/tags" &>/dev/null; then
        echo "Error: Ollama not running. Start it with: ollama serve"
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

build_backend() {
    local bin="$BACKEND_DIR/vulture"
    local need_build=false

    if [[ ! -x "$bin" ]]; then
        need_build=true
    else
        # Rebuild if any .go file is newer than the binary
        while IFS= read -r -d '' f; do
            if [[ "$f" -nt "$bin" ]]; then
                need_build=true
                break
            fi
        done < <(find "$BACKEND_DIR" -name '*.go' -print0 2>/dev/null)
    fi

    if $need_build; then
        echo "  Building backend..."
        if ! (cd "$BACKEND_DIR" && go build -o vulture ./cmd/vulture/) 2>/dev/null; then
            if [[ -x "$bin" ]]; then
                echo "  Warning: Go build failed, using existing binary"
            else
                echo "  Error: Go build failed and no existing binary found"
                exit 1
            fi
        fi
    fi
}

# --- Main ---

[[ $# -lt 1 ]] && usage

PROVIDER="$1"
MODEL="${2:-}"

load_env
export PATH="${GOPATH:-${HOME}/go}/bin:$PATH"

# Read defaults from config.ini
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
OLLAMA_DEFAULT_URL=$(ini_get ollama url "http://localhost:11434")
LMSTUDIO_DEFAULT_URL=$(ini_get lmstudio url "http://localhost:1234/v1")

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
        export OLLAMA_HOST="${OLLAMA_HOST:-$OLLAMA_DEFAULT_URL}"
        ;;

    lmstudio)
        # Always use the local URL — .env may contain a Docker-only address
        # (host.docker.internal) that doesn't resolve on the host.
        export OPENAI_BASE_URL="$LMSTUDIO_DEFAULT_URL"
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
