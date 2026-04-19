#!/usr/bin/env bash
# Non-Docker build script for Vulture.
# Builds backend (Go), CLI (Go), Python agents, and frontend (Node.js).
#
# Usage: scripts/build.sh [component...]
#   scripts/build.sh              # Build everything
#   scripts/build.sh backend      # Build Go backend only
#   scripts/build.sh cli          # Build Go CLI only
#   scripts/build.sh agents       # Build Python agents only
#   scripts/build.sh frontend     # Build frontend only
#   scripts/build.sh backend cli  # Build multiple components
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure pyenv shims are on PATH when running non-interactively.
if [[ -d "$HOME/.pyenv/shims" ]] && [[ ":$PATH:" != *":$HOME/.pyenv/shims:"* ]]; then
    export PATH="$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[build]${NC} $*"; }
ok()   { echo -e "${GREEN}[build]${NC} $*"; }
warn() { echo -e "${YELLOW}[build]${NC} $*"; }
err()  { echo -e "${RED}[build]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_go() {
    if ! command -v go &>/dev/null; then
        err "Go not found. Install with: sudo apt install golang-go"
        return 1
    fi
    log "Go $(go version | awk '{print $3}')"
}

check_python() {
    local py=""
    if command -v python3 &>/dev/null; then py=python3
    elif command -v python &>/dev/null; then py=python
    else
        err "Python 3 not found. Install with: sudo apt install python3 python3-pip python3-venv"
        return 1
    fi
    log "Python $($py --version 2>&1 | awk '{print $2}')" >&2
    echo "$py"
}

check_node() {
    if ! command -v node &>/dev/null; then
        err "Node.js not found. Install with: sudo apt install nodejs npm"
        return 1
    fi
    log "Node $(node --version)"
}

check_pip() {
    local py="$1"
    if ! "$py" -m pip --version &>/dev/null; then
        err "pip not found. Install with: sudo apt install python3-pip"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Build: Go backend
# ---------------------------------------------------------------------------

build_backend() {
    log "Building Go backend..."
    check_go || return 1
    cd "$PROJECT_ROOT/backend"
    go build -o bin/vulture ./cmd/vulture/
    ok "Backend binary: backend/bin/vulture"
}

# ---------------------------------------------------------------------------
# Build: Go CLI
# ---------------------------------------------------------------------------

build_cli() {
    log "Building Go CLI..."
    check_go || return 1
    cd "$PROJECT_ROOT/cli"
    go build -o bin/vulture ./
    ok "CLI binary: cli/bin/vulture"
}

# ---------------------------------------------------------------------------
# Build: Python agents
# ---------------------------------------------------------------------------

build_agents() {
    log "Building Python agents..."
    local py
    py=$(check_python) || return 1
    check_pip "$py" || return 1

    local agents=(
        chaos_engineering
        cwe
        owasp
        prove
        soc2
        ssdf
        xss
        discover
        do178c
        asvs
    )

    # Install shared library first (all agents depend on it)
    log "  Installing shared library..."
    cd "$PROJECT_ROOT/agents/shared"
    "$py" -m pip install -e . --quiet 2>&1 | tail -1 || true
    ok "  shared library installed"

    # Install each agent
    for agent in "${agents[@]}"; do
        local agent_dir="$PROJECT_ROOT/agents/$agent"
        if [[ -f "$agent_dir/pyproject.toml" ]]; then
            log "  Installing $agent agent..."
            cd "$agent_dir"
            "$py" -m pip install -e . --quiet 2>&1 | tail -1 || true
            ok "  $agent agent installed"
        else
            warn "  Skipping $agent (no pyproject.toml)"
        fi
    done

    ok "All agents installed"
}

# ---------------------------------------------------------------------------
# Build: Frontend
# ---------------------------------------------------------------------------

build_frontend() {
    log "Building frontend..."
    check_node || return 1
    cd "$PROJECT_ROOT/frontend"
    npm ci --silent
    npm run build
    ok "Frontend built: frontend/dist/"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local start_time=$SECONDS

    log "Vulture build — $(date)"
    log "Project root: $PROJECT_ROOT"
    echo ""

    local components=("$@")
    if [[ ${#components[@]} -eq 0 ]]; then
        components=(backend cli agents frontend)
    fi

    local failed=0
    for component in "${components[@]}"; do
        case "$component" in
            backend)  build_backend  || ((failed++)) ;;
            cli)      build_cli      || ((failed++)) ;;
            agents)   build_agents   || ((failed++)) ;;
            frontend) build_frontend || ((failed++)) ;;
            *)
                err "Unknown component: $component"
                err "Valid components: backend, cli, agents, frontend"
                ((failed++))
                ;;
        esac
        echo ""
    done

    local elapsed=$((SECONDS - start_time))
    if [[ $failed -eq 0 ]]; then
        ok "Build completed in ${elapsed}s"
    else
        err "Build completed with $failed failure(s) in ${elapsed}s"
        return 1
    fi
}

main "$@"
