#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
CLI_DIR="$PROJECT_ROOT/cli"
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
        # An explicitly exported VULTURE_DB_DSN outranks the .env value:
        # `vulture.sh dev --pg` exports the container's published-port DSN and
        # then execs this script, and sourcing under `set -a` would otherwise
        # overwrite it with whatever stale DSN the .env carries — which is how a
        # .env pointing at the container-internal port silently defeated --pg.
        local _dsn_pre="${VULTURE_DB_DSN:-}"
        set -a
        # shellcheck source=/dev/null
        source "$ENV_FILE"
        set +a
        # Must be an `if`, not `[[ … ]] && export`: as the function's last
        # statement the latter returns 1 when nothing was exported, and `set -e`
        # would abort the launcher.
        if [[ -n "$_dsn_pre" ]]; then
            export VULTURE_DB_DSN="$_dsn_pre"
        fi
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

# Ask LM Studio for the context length it actually LOADED the model with.
#
# Neither the model table nor family inference can know this: the same
# `qwen/qwen3.8-27b` is 32K under Ollama's default and 256K here, because the
# window is a runtime setting of the server, not a property of the model. The
# family table says 32768 for qwen3 (correct for Ollama), so without this the
# window is understated 8x and prompts are truncated for no reason.
#
# `/api/v0/models` is LM Studio's native endpoint and reports
# `loaded_context_length`; it does not exist on other OpenAI-compatible
# servers, so a failure here is silent and the normal resolution applies.
detect_lmstudio_ctx() {
    local base="${1:-$LMSTUDIO_DEFAULT_URL}" want="$2" root ctx
    root="${base%/v1}"; root="${root%/}"
    ctx=$(curl -sf --max-time 5 "$root/api/v0/models" 2>/dev/null | python3 -c "
import sys, json
want = sys.argv[1] if len(sys.argv) > 1 else ''
# Try the id as given AND with a LiteLLM routing prefix removed. \`openai/\` is
# ambiguous: it is LiteLLM's prefix, but it is ALSO part of real LM Studio ids
# such as \`openai/gpt-oss-20b\`, so stripping unconditionally loses the match.
cands = [want]
for pfx in ('openai/', 'litellm/'):
    if want.startswith(pfx):
        cands.append(want[len(pfx):])
try:
    models = json.load(sys.stdin).get('data', [])
except Exception:
    raise SystemExit(0)
def ctx_of(m):
    return m.get('loaded_context_length') or m.get('max_context_length') or 0
def is_embed(m):
    return 'embed' in (m.get('id') or '').lower() or m.get('type') == 'embeddings'
# 1. the requested model, exact id
for m in models:
    if not is_embed(m) and m.get('id') in cands and ctx_of(m):
        print(ctx_of(m)); raise SystemExit(0)
# 2. otherwise whatever chat model is actually loaded. Embeddings are skipped:
#    a loaded embedding model reports a 2048 window and would be picked here,
#    silently capping the chat window to a value from the wrong model.
for m in models:
    if not is_embed(m) and m.get('state') == 'loaded' and ctx_of(m):
        print(ctx_of(m)); raise SystemExit(0)
" "$want" 2>/dev/null)
    [[ "$ctx" =~ ^[0-9]+$ ]] && echo "$ctx"
}

# stale_against <binary> <source-dir> -- true when any .go file is newer than
# the binary, or the binary is missing.
stale_against() {
    local bin="$1" src="$2" f
    [[ -x "$bin" ]] || return 0
    while IFS= read -r -d '' f; do
        [[ "$f" -nt "$bin" ]] && return 0
    done < <(find "$src" -name '*.go' -print0 2>/dev/null)
    return 1
}

# build_cli keeps cli/bin/vulture in step with its sources.
#
# It is a SEPARATE Go module from the backend, with its own bin/vulture, and dev
# mode used to rebuild only the backend. A developer who edited CLI code and ran
# `vulture.sh dev` therefore got a fresh server and a SILENTLY STALE client.
#
# That is not hypothetical: the feature-0080 Ctrl-C cancel shipped, its tests
# passed, and the operator's `cli/bin/vulture` was 33 minutes older than the
# change and contained none of it -- so Ctrl-C did exactly what it had always
# done and the run kept going. The binary the user actually types has to be
# rebuilt by the same command that rebuilds the one they do not.
build_cli() {
    local bin="$CLI_DIR/bin/vulture"
    stale_against "$bin" "$CLI_DIR" || return 0
    echo "  Building CLI..."
    if ! (cd "$CLI_DIR" && go build -o bin/vulture ./) 2>/dev/null; then
        # Non-fatal: dev mode can serve without a current CLI, but say so
        # loudly, because a stale client fails in ways that look like a
        # server-side bug.
        if [[ -x "$bin" ]]; then
            echo "  Warning: CLI build failed — cli/bin/vulture is STALE and may"
            echo "           be missing recent commands or flags."
        else
            echo "  Warning: CLI build failed and no cli/bin/vulture exists."
        fi
    fi
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
# Per-tier model overrides. Absent both, the positional model is used for
# everything — one argument stays sufficient, which is the common case.
SCAN_MODEL=""
VALIDATE_MODEL=""
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
        --scan-model|--generate-model)
            [[ $# -ge 2 ]] || { echo "Error: $1 needs a value"; exit 1; }
            SCAN_MODEL="$2"; shift 2 ;;
        --scan-model=*|--generate-model=*)
            SCAN_MODEL="${1#*=}"; shift ;;
        --validate-model|--judge-model)
            [[ $# -ge 2 ]] || { echo "Error: $1 needs a value"; exit 1; }
            VALIDATE_MODEL="$2"; shift 2 ;;
        --validate-model=*|--judge-model=*)
            VALIDATE_MODEL="${1#*=}"; shift ;;
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
# Substituted here, ahead of the provider block, so an explicit scan model gets
# exactly the same defaulting, prefixing and key checks as a positional one.
# Doing it later would mean re-implementing those rules.
MODEL="${SCAN_MODEL:-$MODEL}"

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


# Apply the provider's model-id convention to an arbitrary model string.
# Extracted so --validate-model gets the SAME treatment as the scan model: an
# unprefixed Gemini id would be routed to the wrong provider entirely.
normalize_model() {
    _nm_provider="$1"; _nm="$2"
    [[ -z "$_nm" ]] && { printf '%s' ""; return; }
    case "$_nm_provider" in
        gemini)
            if [[ "$_nm" != "gemini-pro" && "$_nm" != litellm/* ]]; then
                _nm="litellm/gemini/${_nm#gemini/}"
            fi ;;
        lmstudio)
            [[ "$_nm" != openai/* ]] && _nm="openai/$_nm" ;;
    esac
    printf '%s' "$_nm"
}

# The broker speaks to providers through native adapters and wants a BARE model
# id, so it strips the LiteLLM routing prefix the tiers above add. Mirrors the
# per-provider stripping in the broker block below.
strip_broker_prefix() {
    _sb_provider="$1"; _sb="$2"
    case "$_sb_provider" in
        gemini)    _sb="${_sb#litellm/gemini/}"; _sb="${_sb#gemini/}" ;;
        lmstudio)  _sb="${_sb#openai/}" ;;
        anthropic) _sb="${_sb#litellm/anthropic/}"; _sb="${_sb#anthropic/}" ;;
    esac
    printf '%s' "$_sb"
}

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
        MODEL="$(normalize_model gemini "$MODEL")"
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
        MODEL="$(normalize_model lmstudio "$MODEL")"
        export VULTURE_USE_LLM=true
        export VULTURE_LLM_MODEL="$MODEL"
        # Trust the server's own loaded window over the family table, unless the
        # operator pinned one explicitly.
        if [[ -z "${VULTURE_LLM_CTX_SIZE:-}" ]]; then
            _LM_CTX="$(detect_lmstudio_ctx "$OPENAI_BASE_URL" "$MODEL")"
            if [[ -n "$_LM_CTX" ]]; then
                export VULTURE_LLM_CTX_SIZE="$_LM_CTX"
                echo "  Context:   $_LM_CTX tokens (reported by LM Studio)"
            fi
        fi
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

# ── Per-tier model resolution ────────────────────────────────────────
#
# The model named on the command line is authoritative for EVERY tier that uses
# an LLM, not just generate. The L5 judge reads its own
# VULTURE_VALIDATE_LLM_MODEL, so a stale value in .env used to silently win:
# `dev gemini gemini-2.5-flash` ran generate on Gemini while the judge asked the
# Gemini-fronting broker for `qwen/qwen3.8-27b`, which it cannot serve. Every
# batch failed, and an errored call returns no text, so it surfaced as "JSON
# parse failed twice" — a message about output format, for a request that never
# succeeded.
#
#   (no flags)                 both tiers use the positional model
#   --scan-model M             generate uses M (substituted above)
#   --validate-model M         the judge uses M
#
# A judge model is only meaningful when the run can actually reach it: on the
# broker path the broker fronts ONE provider, so a different validate model is
# accepted but flagged. VULTURE_VALIDATE_LLM_MODEL_EXPLICIT tells the judge the
# value was chosen deliberately, so it does not override it the way it overrides
# a stale environment value.
_SCAN_FINAL="${VULTURE_LLM_MODEL:-}"
if [[ -n "$VALIDATE_MODEL" ]]; then
    _V="$(normalize_model "$PROVIDER" "$VALIDATE_MODEL")"
    if [[ "$USE_BROKER" == "1" ]]; then
        _V="$(strip_broker_prefix "$PROVIDER" "$_V")"
        if [[ -n "$_SCAN_FINAL" && "$_V" != "$_SCAN_FINAL" ]]; then
            echo "  Warning: --validate-model $_V differs from the scan model" \
                 "$_SCAN_FINAL while the broker is on. The broker fronts one" \
                 "provider — if it cannot serve $_V, every judge batch will fail."
        fi
    fi
    export VULTURE_VALIDATE_LLM_MODEL="$_V"
    export VULTURE_VALIDATE_LLM_MODEL_EXPLICIT=1
elif [[ -n "$_SCAN_FINAL" ]]; then
    if [[ -n "${VULTURE_VALIDATE_LLM_MODEL:-}" \
          && "$VULTURE_VALIDATE_LLM_MODEL" != "$_SCAN_FINAL" ]]; then
        echo "  Note: VULTURE_VALIDATE_LLM_MODEL=$VULTURE_VALIDATE_LLM_MODEL" \
             "from the environment is superseded by $_SCAN_FINAL" \
             "(pass --validate-model to choose one explicitly)"
    fi
    export VULTURE_VALIDATE_LLM_MODEL="$_SCAN_FINAL"
    unset VULTURE_VALIDATE_LLM_MODEL_EXPLICIT 2>/dev/null || true
fi

echo "  Provider:  $PROVIDER"
echo "  Model:     ${VULTURE_LLM_MODEL:-$MODEL}"
if [[ -n "${VULTURE_VALIDATE_LLM_MODEL:-}" \
      && "$VULTURE_VALIDATE_LLM_MODEL" != "${VULTURE_LLM_MODEL:-$MODEL}" ]]; then
    echo "  Validate:  $VULTURE_VALIDATE_LLM_MODEL"
fi
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
# Report the DSN the backend will actually dial (password masked). Printing it
# makes a wrong host/port obvious here instead of as a backend "connection
# refused" several seconds later.
if [[ -n "${VULTURE_DB_DSN:-}" ]]; then
    echo "  DB:        $(printf '%s' "$VULTURE_DB_DSN" | sed -E 's#(://[^:]*:)[^@]*(@)#\1***\2#')"
else
    echo "  DB:        sqlite (no VULTURE_DB_DSN set)"
fi
echo

# Test/debug hook: resolve config + print it, but don't boot the
# backend. Used by scripts/tests/test_embed_flags.sh.
if [[ "${VULTURE_LAUNCH_DRY_RUN:-}" == "1" ]]; then
    echo "  (dry run — backend not started)"
    exit 0
fi

build_backend
build_cli
exec "$BACKEND_DIR/vulture" local_start
