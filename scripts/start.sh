#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
# Overridable so tests (and CI) can isolate from a developer's local .env, which
# load_env sources with `set -a` and would otherwise clobber exported vars.
ENV_FILE="${VULTURE_ENV_FILE:-$PROJECT_ROOT/.env}"

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
  gemini [model]       Google Gemini API — remote (default: gemini-pro); needs GEMINI_API_KEY
  ollama [model]       Local Ollama (default: qwen3:1.7b)
  lmstudio [model]     LM Studio (default: local-model)
  skills               Skills only — no LLM (fastest, no API key needed)

Options:
  --embed-url <url>      Embedding endpoint (overrides OPENAI_BASE_URL fallback)
  --embed-model <name>   Embedding model id at that endpoint

Examples:
  scripts/vulture.sh dev openai
  scripts/vulture.sh dev openai gpt-4o
  scripts/vulture.sh dev anthropic claude-sonnet
  GEMINI_API_KEY=AIza... scripts/vulture.sh dev gemini            # remote Gemini (default gemini-pro)
  GEMINI_API_KEY=AIza... scripts/vulture.sh dev gemini gemini-2.5-flash
  scripts/vulture.sh dev ollama qwen3:8b
  scripts/vulture.sh dev lmstudio my-model
  scripts/vulture.sh dev skills

  # chat on NVIDIA, embeddings on local LM Studio:
  OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1 OPENAI_API_KEY=nvapi-... \
    scripts/vulture.sh dev openai z-ai/glm-5.1 \
    --embed-url http://localhost:1234/v1 --embed-model text-embedding-nomic-embed-text-v1.5
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
    [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]] && return 0
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
    [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]] && return 0
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

# Separate optional flags from the positional (provider, model) args so
# the embedding endpoint can be pointed at a different server than the
# chat model — e.g. chat on NVIDIA (OPENAI_BASE_URL) + embeddings on
# local LM Studio (VULTURE_EMBEDDING_URL). Both space ("--embed-url X")
# and equals ("--embed-url=X") forms are accepted.
EMBED_URL=""
EMBED_MODEL=""
USE_BROKER=0
NO_BROKER=0
BROKER_BUDGET=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --embed-url)
            [[ $# -ge 2 ]] || { echo "Error: --embed-url needs a value"; exit 1; }
            EMBED_URL="$2"; shift 2 ;;
        --embed-url=*)
            EMBED_URL="${1#*=}"; shift ;;
        --embed-model)
            [[ $# -ge 2 ]] || { echo "Error: --embed-model needs a value"; exit 1; }
            EMBED_MODEL="$2"; shift 2 ;;
        --embed-model=*)
            EMBED_MODEL="${1#*=}"; shift ;;
        --broker)
            USE_BROKER=1; shift ;;
        --no-broker)
            NO_BROKER=1; shift ;;
        --budget)
            [[ $# -ge 2 ]] || { echo "Error: --budget needs a value"; exit 1; }
            BROKER_BUDGET="$2"; shift 2 ;;
        --budget=*)
            BROKER_BUDGET="${1#*=}"; shift ;;
        *)
            POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]:-}"
[[ $# -lt 1 || -z "$1" ]] && usage

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

    gemini)
        # Remote Google Gemini via LiteLLM's NATIVE provider (GEMINI_API_KEY) —
        # NOT an OpenAI-compat shim. Clear any inherited OPENAI_BASE_URL (e.g. a
        # leftover lmstudio/nvidia value) so calls go to Google, not localhost.
        MODEL="${MODEL:-gemini-pro}"
        require_key GEMINI_API_KEY "Gemini"
        unset OPENAI_BASE_URL 2>/dev/null || true
        # `gemini-pro` is a built-in alias (provider.py → litellm/gemini/...).
        # Any other Gemini model gets the litellm/gemini/ prefix so LiteLLM routes
        # it to Google (parallels the lmstudio arm's openai/ prefixing).
        if [[ "$MODEL" != "gemini-pro" && "$MODEL" != litellm/* ]]; then
            MODEL="litellm/gemini/${MODEL#gemini/}"
        fi
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

# ── Feature 0064 §30: LLM broker is the DEFAULT when LLM is enabled ────────
# The broker (key isolation + budget + egress control) fronts EVERY provider
# via native adapters. It is on by default whenever LLM is on; --no-broker opts
# out. It runs on whichever store the backend uses (SQLite default, or Postgres
# when VULTURE_DB_DSN is set — §29). skills = no LLM = no broker.
if [[ "$NO_BROKER" == "1" || "${VULTURE_USE_LLM:-false}" != "true" ]]; then
    USE_BROKER=0
else
    USE_BROKER=1
fi
if [[ "$USE_BROKER" == "1" ]]; then
    BROKER_CLOUD=0
    case "$PROVIDER" in
        openai)
            BROKER_PROVIDER="openai"; BROKER_LOCAL_EGRESS="off"; BROKER_CLOUD=1
            BROKER_EGRESS="${OPENAI_BASE_URL:-}" ;;
        lmstudio)
            BROKER_PROVIDER="openai-compatible"; BROKER_LOCAL_EGRESS="on"
            BROKER_EGRESS="$LMSTUDIO_DEFAULT_URL"
            # The broker uses the OpenAI SDK → bare model id; drop the LiteLLM openai/ prefix.
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#openai/}" ;;
        ollama)
            BROKER_PROVIDER="openai-compatible"; BROKER_LOCAL_EGRESS="on"
            BROKER_EGRESS="${OLLAMA_DEFAULT_URL%/}/v1" ;;
        gemini)
            # §30 native generateContent adapter (default Google endpoint).
            BROKER_PROVIDER="gemini"; BROKER_LOCAL_EGRESS="off"; BROKER_CLOUD=1; BROKER_EGRESS=""
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#litellm/gemini/}"; export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#gemini/}" ;;
        anthropic)
            # §30 native Messages adapter (default Anthropic endpoint).
            BROKER_PROVIDER="anthropic"; BROKER_LOCAL_EGRESS="off"; BROKER_CLOUD=1; BROKER_EGRESS=""
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#litellm/anthropic/}"; export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#anthropic/}" ;;
        *)
            echo "Error: provider '$PROVIDER' has no broker adapter. Use --no-broker to bypass."
            exit 1 ;;
    esac
    export VULTURE_LLM_BROKER=on
    export VULTURE_LLM_BROKER_LISTEN="${VULTURE_LLM_BROKER_LISTEN:-127.0.0.1:8090}"
    export VULTURE_LLM_BROKER_URL="${VULTURE_LLM_BROKER_URL:-http://localhost:8090/v1}"
    export VULTURE_LLM_BROKER_PROVIDER="$BROKER_PROVIDER"
    [[ -n "$BROKER_EGRESS" ]] && export VULTURE_LLM_BROKER_PROVIDER_BASE_URL="$BROKER_EGRESS"
    export VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS="$BROKER_LOCAL_EGRESS"
    [[ -n "$BROKER_BUDGET" ]] && export VULTURE_LLM_BUDGET_USD="$BROKER_BUDGET"
    # A real cloud key is now brokered — flag the pending crypto sign-off (§27).
    if [[ "$BROKER_CLOUD" == "1" ]]; then
        echo "  Note: brokering a cloud provider with a real key. The ES256 + budget-CAS"
        echo "        human sign-off is still pending (§25.3/§27) — pass --no-broker to opt out."
    fi
fi

# Embedding endpoint override. Decouples the pgvector embedding client
# from OPENAI_BASE_URL — without this it falls back to the chat
# endpoint (NVIDIA), which has no matching /embeddings route → 404s.
# Point it at a real embedding server (local LM Studio / Ollama).
if [[ -n "$EMBED_URL" ]]; then
    export VULTURE_EMBEDDING_URL="$EMBED_URL"
fi
if [[ -n "$EMBED_MODEL" ]]; then
    export VULTURE_EMBEDDING_MODEL="$EMBED_MODEL"
fi

echo "  Provider:  $PROVIDER"
echo "  Model:     ${VULTURE_LLM_MODEL:-$MODEL}"
echo "  LLM:       ${VULTURE_USE_LLM:-false}"
if [[ "${VULTURE_LLM_BROKER:-off}" == "on" ]]; then
    echo "  Broker:    on"
    echo "  Broker provider:     ${VULTURE_LLM_BROKER_PROVIDER}"
    echo "  Broker egress:       ${VULTURE_LLM_BROKER_PROVIDER_BASE_URL:-default (${VULTURE_LLM_BROKER_PROVIDER})}"
    echo "  Broker local-egress: ${VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS}"
    [[ -n "${VULTURE_LLM_BUDGET_USD:-}" ]] && echo "  Broker budget:       \$${VULTURE_LLM_BUDGET_USD}"
fi
[[ -n "${VULTURE_EMBEDDING_URL:-}" ]]   && echo "  Embed URL: ${VULTURE_EMBEDDING_URL}"
[[ -n "${VULTURE_EMBEDDING_MODEL:-}" ]] && echo "  Embed model: ${VULTURE_EMBEDDING_MODEL}"
echo

# Test/debug hook: resolve config + print it, but don't boot the
# backend. Used by scripts/tests/test_embed_flags.sh.
if [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]]; then
    echo "  (dry run — backend not started)"
    exit 0
fi

build_backend
exec "$BACKEND_DIR/vulture" local_start
