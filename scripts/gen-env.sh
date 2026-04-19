#!/usr/bin/env bash
# Generates .env from config.ini for docker compose consumption.
# Usage: scripts/gen-env.sh [config.ini path] [output .env path]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INI="${1:-$SCRIPT_DIR/../config.ini}"
OUT="${2:-$SCRIPT_DIR/../.env}"

if [[ ! -f "$INI" ]]; then
    echo "Error: config.ini not found at $INI"
    exit 1
fi

ini_get() {
    local section="$1" key="$2"
    awk -v sec="[$section]" -v k="$key" '
        /^\[/ { in_sec = ($0 == sec) }
        in_sec && match($0, "^[[:space:]]*"k"[[:space:]]*=") {
            sub(/^[^=]*=[[:space:]]*/, ""); print; exit
        }
    ' "$INI"
}

# Pre-compute JWT secret before heredoc to avoid race window
_JWT_VAL=$(ini_get auth jwt_secret)
if [[ -z "$_JWT_VAL" ]]; then
    _JWT_VAL=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi

cat > "$OUT" <<EOF
# Auto-generated from config.ini — do not edit directly.
# Run: scripts/gen-env.sh (or make gen-env)

# Application
VULTURE_APP_NAME=$(ini_get app name)

# Ports
VULTURE_BACKEND_PORT=$(ini_get ports backend)

# Auto-emit VULTURE_AGENT_<NAME>_PORT= for every agent_* key in [ports].
# Keeps the env in sync with config.ini without a hardcoded list.
while IFS='=' read -r agent_key port; do
    # e.g. agent_asvs=28010 -> VULTURE_AGENT_ASVS_PORT=28010
    upper=$(echo "${agent_key#agent_}" | tr '[:lower:]' '[:upper:]')
    echo "VULTURE_AGENT_${upper}_PORT=${port}"
done < <(awk '
    /^\[ports\]/          { in_sec = 1; next }
    /^\[/                 { in_sec = 0 }
    in_sec && /^[[:space:]]*agent_/ {
        key = $1; sub(/=.*/, "", key); gsub(/[[:space:]]/, "", key)
        val = $0; sub(/^[^=]*=[[:space:]]*/, "", val); gsub(/[[:space:]]/, "", val)
        if (val ~ /^[0-9]+$/) printf "%s=%s\n", key, val
    }
' "$PROJECT_ROOT/config.ini")

VULTURE_FRONTEND_INTERNAL=$(ini_get ports frontend_internal)
VULTURE_FRONTEND_HOST=$(ini_get ports frontend_host)
VITE_DEV_PORT=$(ini_get ports frontend_internal)
VULTURE_POSTGRES_INTERNAL_PORT=$(ini_get ports postgres_internal)
VULTURE_POSTGRES_HOST_PORT=$(ini_get ports postgres_host)

# Database
VULTURE_DB_MODE=$(ini_get database mode)
VULTURE_DB_NAME=$(ini_get database name)
VULTURE_DB_USER=$(ini_get database user)
VULTURE_DB_PASSWORD=$(ini_get database password)
VULTURE_DB_SQLITE_PATH=$(ini_get database sqlite_path)
VULTURE_DB_HOST=$(ini_get database host)
VULTURE_DB_PORT=$(ini_get database port)
VULTURE_DB_SSLMODE=$(ini_get database sslmode)
VULTURE_NEON_DSN=$(ini_get database neon_dsn)
EOF

# Compute VULTURE_DB_DSN from mode
_DB_MODE=$(ini_get database mode)
_DB_DSN=""
case "$_DB_MODE" in
    postgres)
        _u=$(ini_get database user)
        _p=$(ini_get database password)
        _h=$(ini_get database host)
        _port=$(ini_get database port)
        _n=$(ini_get database name)
        _ssl=$(ini_get database sslmode)
        _DB_DSN="postgres://${_u}:${_p}@${_h}:${_port}/${_n}?sslmode=${_ssl:-disable}"
        ;;
    neon)
        _DB_DSN=$(ini_get database neon_dsn)
        if [[ -z "$_DB_DSN" ]]; then
            echo "  Warning: mode=neon but neon_dsn is empty in config.ini"
        fi
        ;;
    sqlite|"")
        _DB_DSN=""
        ;;
    *)
        echo "  Warning: unknown database mode '$_DB_MODE', defaulting to sqlite"
        _DB_DSN=""
        ;;
esac

cat >> "$OUT" <<EOF
VULTURE_DB_DSN=$_DB_DSN

# Auth
VULTURE_JWT_SECRET=$_JWT_VAL

# API keys
OPENAI_API_KEY=$(ini_get api_keys openai)
ANTHROPIC_API_KEY=$(ini_get api_keys anthropic)
GEMINI_API_KEY=$(ini_get api_keys gemini)
EOF

# Continue writing the rest of .env
cat >> "$OUT" <<EOF

# Embedding
VULTURE_EMBEDDING_URL=$(ini_get embedding url)
VULTURE_EMBEDDING_MODEL=$(ini_get embedding model)

# LLM defaults
VULTURE_LLM_MODEL_DEFAULT=$(ini_get llm model)
VULTURE_LLM_CTX_SIZE=$(ini_get llm context_size)

# External services
VULTURE_OLLAMA_URL=$(ini_get ollama url)
VULTURE_LMSTUDIO_URL=$(ini_get lmstudio url)
EOF

echo "  Generated $OUT from $INI"
