#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${VULTURE_ENV_FILE:-$PROJECT_ROOT/.env}"

usage() {
    cat <<'EOF'
Usage: scripts/vulture.sh server <provider> [model]

Providers:
  openai [model]       OpenAI API (default: gpt-4o)
  anthropic [model]    Anthropic API (default: claude-sonnet)
  gemini [model]       Remote Google Gemini via GEMINI_API_KEY (default: gemini-pro)
  ollama [model]       Local Ollama (default: qwen3:1.7b)
  lmstudio [model]     LM Studio (default: local-model)
  skills               Skills only — no LLM (fastest, no API key needed)

Options:
  --embed-url <url>      Embedding endpoint (overrides OPENAI_BASE_URL fallback).
                         In Docker, reach a host server via host.docker.internal.
  --embed-model <name>   Embedding model id at that endpoint

Examples:
  scripts/vulture.sh server openai
  scripts/vulture.sh server openai gpt-4o
  scripts/vulture.sh server anthropic claude-sonnet
  scripts/vulture.sh server ollama qwen3:8b
  scripts/vulture.sh server lmstudio my-model
  scripts/vulture.sh server skills
  scripts/vulture.sh server openai z-ai/glm-5.1 \
    --embed-url http://host.docker.internal:1234/v1 --embed-model nomic-embed-text
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
    [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]] && return 0
    local url="${OLLAMA_DEFAULT_URL:-http://localhost:11434}"
    if ! curl -sf "$url/api/tags" &>/dev/null; then
        echo "Error: Ollama not reachable at $url"
        echo "  Start it with: ollama serve"
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

# Detect the first embedding model loaded in LM Studio.
detect_lmstudio_embedding_model() {
    local url="${OPENAI_BASE_URL:-$LMSTUDIO_DEFAULT_URL}"
    curl -sf "$url/models" 2>/dev/null \
        | python3 -c "import sys,json; models=[m['id'] for m in json.load(sys.stdin)['data'] if 'embed' in m['id'].lower()]; print(models[0] if models else '')" 2>/dev/null \
        || true
}

# Verify ports required by docker-compose are not already bound by non-docker processes.
check_ports_free() {
    local ports="$1"
    local busy=""
    for p in $ports; do
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":$p$"; then
            # Port is bound — check if it's a docker container, which is fine.
            if ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE "[:]$p->"; then
                busy="$busy $p"
            fi
        fi
    done
    if [[ -n "$busy" ]]; then
        echo "Error: ports in use by non-docker processes:$busy"
        echo "  Identify with: ss -tlnp | grep -E '$(echo "$busy" | tr ' ' '|')'"
        echo "  Stop them, then retry. If they are root-owned stale processes, try:"
        echo "    sudo kill -9 \$(pgrep -f \"vulture|uvicorn.*agent|vite.*2300\")"
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
    [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]] && return 0
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

# Optional --embed-url / --embed-model flags (see start.sh for rationale):
# point the pgvector embedding client at a different server than the chat
# model. In Docker (Mode B) a host-local embedding server is reached via
# host.docker.internal, e.g. --embed-url http://host.docker.internal:1234/v1
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

    gemini)
        # Remote Google Gemini via LiteLLM's NATIVE provider (GEMINI_API_KEY) —
        # NOT an OpenAI-compat shim. Clear any inherited OPENAI_BASE_URL so the
        # .env-generation block below does not propagate a stale base URL to the
        # containers (which would re-route Gemini calls to the wrong endpoint).
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
        # Auto-configure embeddings if a compatible model is loaded in LM Studio
        if [[ -z "${VULTURE_EMBEDDING_MODEL:-}" ]]; then
            _embed_model=$(detect_lmstudio_embedding_model)
            if [[ -n "$_embed_model" ]]; then
                export VULTURE_EMBEDDING_MODEL="$_embed_model"
                export VULTURE_EMBEDDING_URL="http://host.docker.internal:1234/v1"
                echo "  Auto-detected embedding model: $_embed_model"
            fi
        fi
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

# ── Feature 0064 §30: LLM broker is the DEFAULT when LLM is enabled ────────
# The broker (sole provider-key holder + budget/egress gateway; agents get a
# scoped per-run token) fronts EVERY provider via native adapters. On by
# default whenever LLM is on; --no-broker opts out. It listens inside the
# backend container (0.0.0.0:8090, NOT host-published); agents reach it at
# http://backend:8090/v1. skills = no LLM = no broker.
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
            # The broker runs in the backend container: a host LM Studio is
            # reached via host.docker.internal, and it wants the bare model id.
            BROKER_EGRESS="http://host.docker.internal:1234/v1"
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#openai/}" ;;
        ollama)
            BROKER_PROVIDER="openai-compatible"; BROKER_LOCAL_EGRESS="on"
            BROKER_EGRESS="http://host.docker.internal:11434/v1"
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#ollama/}" ;;
        gemini)
            BROKER_PROVIDER="gemini"; BROKER_LOCAL_EGRESS="off"; BROKER_CLOUD=1; BROKER_EGRESS=""
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#litellm/gemini/}"; export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#gemini/}" ;;
        anthropic)
            BROKER_PROVIDER="anthropic"; BROKER_LOCAL_EGRESS="off"; BROKER_CLOUD=1; BROKER_EGRESS=""
            export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#litellm/anthropic/}"; export VULTURE_LLM_MODEL="${VULTURE_LLM_MODEL#anthropic/}" ;;
        *)
            echo "Error: provider '$PROVIDER' has no broker adapter. Use --no-broker to bypass."
            exit 1 ;;
    esac
    export VULTURE_LLM_BROKER=on
    export VULTURE_LLM_BROKER_LISTEN="${VULTURE_LLM_BROKER_LISTEN:-0.0.0.0:8090}"
    export VULTURE_LLM_BROKER_URL="${VULTURE_LLM_BROKER_URL:-http://backend:8090/v1}"
    export VULTURE_LLM_BROKER_PROVIDER="$BROKER_PROVIDER"
    [[ -n "$BROKER_EGRESS" ]] && export VULTURE_LLM_BROKER_PROVIDER_BASE_URL="$BROKER_EGRESS"
    export VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS="$BROKER_LOCAL_EGRESS"
    [[ -n "$BROKER_BUDGET" ]] && export VULTURE_LLM_BUDGET_USD="$BROKER_BUDGET"
    # N1 key isolation: withhold the provider key from the agent containers
    # (empty-but-set → docker-compose's `-` default keeps it empty; the backend
    # still receives the real OPENAI_API_KEY / ANTHROPIC_API_KEY).
    export VULTURE_AGENT_OPENAI_API_KEY=""
    export VULTURE_AGENT_ANTHROPIC_API_KEY=""
    export VULTURE_AGENT_GEMINI_API_KEY=""
    # §30: also withhold the provider base URL — the agent routes via the broker.
    export VULTURE_AGENT_OPENAI_BASE_URL=""
    # A real cloud key is now brokered — flag the pending crypto sign-off (§27).
    if [[ "$BROKER_CLOUD" == "1" ]]; then
        echo "  Note: brokering a cloud provider with a real key. The ES256 + budget-CAS"
        echo "        human sign-off is still pending (§25.3/§27) — pass --no-broker to opt out."
    fi
fi

# Embedding endpoint override (see start.sh). Exported here so the
# .env-generation block below propagates it to the containers.
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
    echo "  Broker:    on (key isolation — agents receive NO provider key)"
    echo "  Broker provider:     ${VULTURE_LLM_BROKER_PROVIDER}"
    echo "  Broker egress:       ${VULTURE_LLM_BROKER_PROVIDER_BASE_URL:-default (${VULTURE_LLM_BROKER_PROVIDER})}"
    echo "  Broker local-egress: ${VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS}"
    [[ -n "${VULTURE_LLM_BUDGET_USD:-}" ]] && echo "  Broker budget:       \$${VULTURE_LLM_BUDGET_USD}"
fi
[[ -n "${VULTURE_EMBEDDING_URL:-}" ]]   && echo "  Embed URL: ${VULTURE_EMBEDDING_URL}"
[[ -n "${VULTURE_EMBEDDING_MODEL:-}" ]] && echo "  Embed model: ${VULTURE_EMBEDDING_MODEL}"
echo

# Test/debug hook: resolve config + print it, but don't touch docker/.env.
if [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]]; then
    echo "  (dry run — compose not started)"
    exit 0
fi

# Port conflict pre-check (docker containers are fine; external binds are not)
check_ports_free "$BACKEND_PORT $FRONTEND_PORT $POSTGRES_PORT"

# Regenerate .env cleanly from config.ini (avoids accumulation across runs)
echo "  Generating .env..."
"$SCRIPT_DIR/gen-env.sh"

# Append LLM-specific vars to the freshly generated .env
{
    echo ""
    echo "# LLM provider (set by prod_start.sh)"
    echo "VULTURE_USE_LLM=${VULTURE_USE_LLM:-false}"
    [[ -n "${VULTURE_LLM_MODEL:-}" ]] && echo "VULTURE_LLM_MODEL=$VULTURE_LLM_MODEL"
    [[ -n "${OPENAI_API_KEY:-}" ]] && echo "OPENAI_API_KEY=$OPENAI_API_KEY"
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] && echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
    [[ -n "${GEMINI_API_KEY:-}" ]] && echo "GEMINI_API_KEY=$GEMINI_API_KEY"
    [[ -n "${OPENAI_BASE_URL:-}" ]] && echo "OPENAI_BASE_URL=$OPENAI_BASE_URL"
    [[ -n "${OLLAMA_API_BASE:-}" ]] && echo "OLLAMA_API_BASE=$OLLAMA_API_BASE"
    [[ -n "${VULTURE_EMBEDDING_URL:-}" ]] && echo "VULTURE_EMBEDDING_URL=$VULTURE_EMBEDDING_URL"
    [[ -n "${VULTURE_EMBEDDING_MODEL:-}" ]] && echo "VULTURE_EMBEDDING_MODEL=$VULTURE_EMBEDDING_MODEL"
    # Feature 0064: LLM broker (only written when --broker was passed)
    if [[ "${VULTURE_LLM_BROKER:-off}" == "on" ]]; then
        echo "VULTURE_LLM_BROKER=on"
        echo "VULTURE_LLM_BROKER_LISTEN=${VULTURE_LLM_BROKER_LISTEN}"
        echo "VULTURE_LLM_BROKER_URL=${VULTURE_LLM_BROKER_URL}"
        echo "VULTURE_LLM_BROKER_PROVIDER=${VULTURE_LLM_BROKER_PROVIDER}"
        [[ -n "${VULTURE_LLM_BROKER_PROVIDER_BASE_URL:-}" ]] && echo "VULTURE_LLM_BROKER_PROVIDER_BASE_URL=${VULTURE_LLM_BROKER_PROVIDER_BASE_URL}"
        echo "VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS=${VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS}"
        [[ -n "${VULTURE_LLM_BROKER_MINT_KEY:-}" ]] && echo "VULTURE_LLM_BROKER_MINT_KEY=${VULTURE_LLM_BROKER_MINT_KEY}"
        [[ -n "${VULTURE_LLM_BUDGET_USD:-}" ]] && echo "VULTURE_LLM_BUDGET_USD=${VULTURE_LLM_BUDGET_USD}"
        # Key isolation: agents get empty provider keys; backend keeps the real ones.
        echo "VULTURE_AGENT_OPENAI_API_KEY="
        echo "VULTURE_AGENT_ANTHROPIC_API_KEY="
        echo "VULTURE_AGENT_GEMINI_API_KEY="
        echo "VULTURE_AGENT_OPENAI_BASE_URL="
    fi
} >> "$ENV_FILE"

# Build shared agent base image (once, reused by all 9 agents: chaos, owasp, soc2,
# cwe, prove, xss, ssdf, discover, do178c)
echo "  Building agent base image..."
docker build -t vulture-agent-base:latest -f "$PROJECT_ROOT/agents/Dockerfile.base" "$PROJECT_ROOT/agents/" -q

# Launch docker compose
echo "  Starting docker compose..."
echo
# COMPOSE_BAKE=false: agents build FROM the locally-built
# vulture-agent-base:latest (above), which is never pushed to a registry.
# Compose's bake delegation uses a buildx builder that does not share the
# daemon image store and would try to PULL the base (403). The classic
# daemon build path resolves it from the local image store.
COMPOSE_BAKE=false docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d --build

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
echo "  Stop:       scripts/vulture.sh stop docker"
echo "  ──────────────────────────────────────────"
echo
