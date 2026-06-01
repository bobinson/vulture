#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Vulture — Unified launcher for all deployment modes.
#
# Usage:
#   scripts/vulture.sh <command> [options]
#
# Commands:
#   build              Build all components (Go backend + CLI + Python agents + frontend)
#   build docker       Build Docker images (base + all services)
#   build installer    Build a native-installer tarball for the current host (Mode E, feature 0044)
#
#   dev <provider>     Mode A: Dev-local — bare metal, everything on one machine
#   server <provider>  Mode B: Central server — Docker + remote DB
#   viewer             Mode C: Read-only viewer VM — Docker, no agents
#
#   stop               Stop Mode A (bare metal processes)
#   stop docker        Stop Mode B/C (docker compose down)
#
# Providers (for dev/server):
#   skills             Skills only, no LLM (fastest, no API key needed)
#   lmstudio [model]   LM Studio (auto-detects loaded model)
#   ollama [model]     Local Ollama (default: qwen3:1.7b)
#   openai [model]     OpenAI API (default: gpt-4o)
#   anthropic [model]  Anthropic API (default: claude-sonnet)
#
# CI client (Mode D) doesn't need this script — use the CLI directly:
#   vulture scan <git-url> --api-key <key> --server <url> --wait --exit-on high
#
# Examples:
#   scripts/vulture.sh build                     # Build everything locally
#   scripts/vulture.sh build docker              # Build Docker images
#   scripts/vulture.sh dev skills                # Dev-local, skills only
#   scripts/vulture.sh dev lmstudio              # Dev-local + LM Studio (SQLite)
#   scripts/vulture.sh dev lmstudio --pg         # Dev-local + LM Studio + Postgres container
#   scripts/vulture.sh dev openai gpt-4o         # Dev-local + OpenAI
#   scripts/vulture.sh server lmstudio           # Central server + LM Studio (Docker)
#   scripts/vulture.sh server skills             # Central server, skills only (Docker)
#   scripts/vulture.sh viewer                    # Read-only viewer VM (Docker)
#   scripts/vulture.sh stop                      # Stop dev-local
#   scripts/vulture.sh stop docker               # Stop Docker services
#   scripts/vulture.sh stop docker --volumes     # Stop + delete DB volumes
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    sed -n '3,/^# ────/p' "$0" | sed 's/^# \?//'
    exit 1
}

[[ $# -lt 1 || "${1:-}" == "--help" || "${1:-}" == "-h" ]] && usage

COMMAND="$1"; shift

case "$COMMAND" in

    # ── Build ─────────────────────────────────────────────────────────────
    build)
        if [[ "${1:-}" == "docker" ]]; then
            shift
            exec "$SCRIPT_DIR/build-docker.sh" "$@"
        fi
        if [[ "${1:-}" == "installer" ]]; then
            shift
            # Mode E: native installer tarball — feature 0044.
            # Usage: scripts/vulture.sh build installer [<version>] [<os>] [<arch>]
            VERSION=${1:-v0.0.0-dev}
            OS=${2:-$(uname -s | tr '[:upper:]' '[:lower:]')}
            ARCH=${3:-$(uname -m)}
            case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac
            exec "$SCRIPT_DIR/build-release.sh" "$VERSION" "$OS" "$ARCH"
        fi
        exec "$SCRIPT_DIR/build.sh" "$@"
        ;;

    # ── Mode A: Dev-local (bare metal) ────────────────────────────────────
    dev)
        [[ $# -lt 1 ]] && { echo "Usage: scripts/vulture.sh dev <provider> [model] [--embed-url URL] [--embed-model NAME] [--pg]"; exit 1; }
        # --pg flag (any position): bring up the postgres docker
        # container and export VULTURE_DB_DSN so local_start uses
        # Postgres instead of SQLite.
        args=()
        use_pg=0
        for a in "$@"; do
            if [[ "$a" == "--pg" || "$a" == "--postgres" ]]; then
                use_pg=1
            else
                args+=("$a")
            fi
        done
        if [[ $use_pg -eq 1 ]]; then
            if [[ -f "$PROJECT_ROOT/.env" ]]; then
                set -a; source "$PROJECT_ROOT/.env"; set +a
            fi
            : "${VULTURE_DB_USER:=vulture}"
            : "${VULTURE_DB_NAME:=vulture}"
            : "${VULTURE_POSTGRES_HOST_PORT:=25433}"
            if [[ -z "${VULTURE_DB_PASSWORD:-}" ]]; then
                echo "Error: VULTURE_DB_PASSWORD must be set (in $PROJECT_ROOT/.env or env)"
                exit 1
            fi
            echo "  Starting postgres container on host port $VULTURE_POSTGRES_HOST_PORT ..."
            ( cd "$PROJECT_ROOT" && docker compose up -d postgres ) || {
                echo "Error: failed to bring up postgres container"; exit 1; }
            export VULTURE_DB_DSN="postgres://${VULTURE_DB_USER}:${VULTURE_DB_PASSWORD}@localhost:${VULTURE_POSTGRES_HOST_PORT}/${VULTURE_DB_NAME}?sslmode=disable"
            echo "  DB: $VULTURE_DB_DSN" | sed -E 's#(:)[^@/]+(@)#\1***\2#'
        fi
        exec "$SCRIPT_DIR/start.sh" "${args[@]}"
        ;;

    # ── Mode B: Central server (Docker) ───────────────────────────────────
    server)
        [[ $# -lt 1 ]] && { echo "Usage: scripts/vulture.sh server <provider> [model]"; exit 1; }
        exec "$SCRIPT_DIR/prod_start.sh" "$@"
        ;;

    # ── Mode C: Read-only viewer VM (Docker) ──────────────────────────────
    viewer)
        echo
        echo "  Vulture Viewer (read-only mode)"
        echo

        # Validate required env vars
        if [[ -f "$PROJECT_ROOT/.env" ]]; then
            set -a; source "$PROJECT_ROOT/.env"; set +a
        fi
        if [[ -z "${VULTURE_DB_DSN:-}" ]]; then
            echo "Error: VULTURE_DB_DSN must be set in .env (remote Postgres/Neon DSN)"
            echo "  Example: VULTURE_DB_DSN=postgres://user:pass@ep-xxx-pooler.neon.tech/vulture?sslmode=require"
            exit 1
        fi
        if [[ -z "${VULTURE_JWT_SECRET:-}" ]]; then
            echo "Error: VULTURE_JWT_SECRET must be set in .env (must match the writer server)"
            exit 1
        fi

        echo "  DB:       ${VULTURE_DB_DSN%%@*}@..."
        echo "  Compose:  docker-compose.readonly.yml"
        echo

        cd "$PROJECT_ROOT"
        docker compose -f docker-compose.readonly.yml up -d --build

        echo
        echo "  ──────────────────────────────────────────"
        echo "  Vulture Viewer is running (read-only)"
        echo
        echo "  Frontend:  http://localhost:${VULTURE_FRONTEND_HOST:-23001}"
        echo "  Backend:   http://localhost:${VULTURE_BACKEND_PORT:-28080} (read-only)"
        echo
        echo "  Stop:      scripts/vulture.sh stop docker"
        echo "  ──────────────────────────────────────────"
        echo
        ;;

    # ── Stop ──────────────────────────────────────────────────────────────
    stop)
        if [[ "${1:-}" == "docker" ]]; then
            shift
            exec "$SCRIPT_DIR/prod_stop.sh" "$@"
        fi
        exec "$SCRIPT_DIR/stop.sh" "$@"
        ;;

    *)
        echo "Error: unknown command '$COMMAND'"
        echo
        usage
        ;;
esac
