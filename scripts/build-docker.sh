#!/usr/bin/env bash
# Docker build script for Vulture.
# Builds all Docker images via docker compose.
#
# Usage: scripts/vulture.sh build docker [options]
#   scripts/vulture.sh build docker              # Build all services
#   scripts/vulture.sh build docker --no-cache   # Build without Docker cache
#   scripts/vulture.sh build docker --up         # Build and start services
#   scripts/vulture.sh build docker --service backend   # Build specific service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[docker-build]${NC} $*"; }
ok()   { echo -e "${GREEN}[docker-build]${NC} $*"; }
warn() { echo -e "${YELLOW}[docker-build]${NC} $*"; }
err()  { echo -e "${RED}[docker-build]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

NO_CACHE=""
START_AFTER=false
SERVICE=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cache) NO_CACHE="--no-cache"; shift ;;
        --up)       START_AFTER=true; shift ;;
        --service)  SERVICE="$2"; shift 2 ;;
        -h|--help)
            cat <<'EOF'
Usage: scripts/vulture.sh build docker [options]

Options:
  --no-cache         Build without Docker cache
  --up               Start services after building
  --service <name>   Build a specific service (e.g., backend, frontend, agent-cwe)
  -h, --help         Show this help

Services: postgres, backend, frontend, agent-chaos, agent-owasp, agent-soc2,
          agent-cwe, agent-prove, agent-xss, agent-ssdf, agent-discover,
          agent-do178c, agent-asvs
EOF
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker not found. Install from: https://docs.docker.com/engine/install/ubuntu/"
        return 1
    fi
    if ! docker info &>/dev/null; then
        err "Docker daemon not running or permission denied."
        err "Try: sudo systemctl start docker"
        err "Or add your user: sudo usermod -aG docker \$USER"
        return 1
    fi
    log "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
}

check_compose() {
    if docker compose version &>/dev/null; then
        log "Docker Compose $(docker compose version --short)"
        return 0
    fi
    err "Docker Compose not found."
    err "Install with: sudo apt install docker-compose-plugin"
    return 1
}

# ---------------------------------------------------------------------------
# Generate .env from config.ini
# ---------------------------------------------------------------------------

generate_env() {
    local ini="$PROJECT_ROOT/config.ini"
    local env="$PROJECT_ROOT/.env"

    if [[ -f "$ini" ]]; then
        log "Generating .env from config.ini..."
        bash "$SCRIPT_DIR/gen-env.sh" "$ini" "$env"
    elif [[ -f "$env" ]]; then
        warn "No config.ini found, using existing .env"
    else
        warn "No config.ini or .env found. Docker Compose may use defaults."
        warn "Create config.ini or copy from config.ini.example if available."
    fi
}

# ---------------------------------------------------------------------------
# Build agent base image
# ---------------------------------------------------------------------------

build_base_image() {
    log "Building agent base image (vulture-agent-base)..."
    docker build \
        $NO_CACHE \
        -t vulture-agent-base:latest \
        -f "$PROJECT_ROOT/agents/Dockerfile.base" \
        "$PROJECT_ROOT/agents/"
    ok "Agent base image built"
}

# ---------------------------------------------------------------------------
# Build services via docker compose
# ---------------------------------------------------------------------------

build_services() {
    cd "$PROJECT_ROOT"

    if [[ -n "$SERVICE" ]]; then
        log "Building service: $SERVICE"
        docker compose build $NO_CACHE "$SERVICE"
    else
        log "Building all services..."
        docker compose build $NO_CACHE
    fi
    ok "Docker images built"
}

# ---------------------------------------------------------------------------
# Optionally start services
# ---------------------------------------------------------------------------

start_services() {
    cd "$PROJECT_ROOT"
    if [[ -n "$SERVICE" ]]; then
        log "Starting service: $SERVICE"
        docker compose up -d "$SERVICE"
    else
        log "Starting all services..."
        docker compose up -d
    fi
    ok "Services started"
    echo ""
    docker compose ps
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local start_time=$SECONDS

    log "Vulture Docker build — $(date)"
    log "Project root: $PROJECT_ROOT"
    echo ""

    check_docker || exit 1
    check_compose || exit 1
    echo ""

    generate_env
    echo ""

    build_base_image
    echo ""

    build_services
    echo ""

    if $START_AFTER; then
        start_services
        echo ""
    fi

    local elapsed=$((SECONDS - start_time))
    ok "Docker build completed in ${elapsed}s"

    if ! $START_AFTER; then
        echo ""
        log "To start services: docker compose up -d"
        log "To start after build: scripts/vulture.sh build docker --up"
    fi
}

main
