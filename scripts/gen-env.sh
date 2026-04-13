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
VULTURE_AGENT_CHAOS_PORT=$(ini_get ports agent_chaos)
VULTURE_AGENT_OWASP_PORT=$(ini_get ports agent_owasp)
VULTURE_AGENT_SOC2_PORT=$(ini_get ports agent_soc2)
VULTURE_AGENT_CWE_PORT=$(ini_get ports agent_cwe)
VULTURE_AGENT_PROVE_PORT=$(ini_get ports agent_prove)
VULTURE_AGENT_XSS_PORT=$(ini_get ports agent_xss)
VULTURE_AGENT_SSDF_PORT=$(ini_get ports agent_ssdf)
VULTURE_AGENT_DISCOVER_PORT=$(ini_get ports agent_discover)
VULTURE_FRONTEND_INTERNAL=$(ini_get ports frontend_internal)
VULTURE_FRONTEND_HOST=$(ini_get ports frontend_host)
VITE_DEV_PORT=$(ini_get ports frontend_internal)
VULTURE_POSTGRES_INTERNAL_PORT=$(ini_get ports postgres_internal)
VULTURE_POSTGRES_HOST_PORT=$(ini_get ports postgres_host)

# Database
VULTURE_DB_NAME=$(ini_get database name)
VULTURE_DB_USER=$(ini_get database user)
VULTURE_DB_PASSWORD=$(ini_get database password)
VULTURE_DB_SQLITE_PATH=$(ini_get database sqlite_path)

# Auth
VULTURE_JWT_SECRET=$_JWT_VAL
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
