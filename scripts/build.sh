#!/usr/bin/env bash
# Non-Docker build script for Vulture.
# Builds backend (Go), CLI (Go), Python agents, and frontend (Node.js).
#
# Usage: scripts/vulture.sh build [component...]
#   scripts/vulture.sh build              # Build everything
#   scripts/vulture.sh build backend      # Build Go backend only
#   scripts/vulture.sh build cli          # Build Go CLI only
#   scripts/vulture.sh build agents       # Build Python agents only
#   scripts/vulture.sh build frontend     # Build frontend only
#   scripts/vulture.sh build backend cli  # Build multiple components
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure pyenv shims are on PATH when running non-interactively.
if [[ -d "$HOME/.pyenv/shims" ]] && [[ ":$PATH:" != *":$HOME/.pyenv/shims:"* ]]; then
    export PATH="$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH"
fi

# Prefer the user's installed Go at $HOME/go/bin/go over a possibly-older
# Debian-packaged /usr/bin/go. With this on PATH the rest of the script
# can just call `go` and it'll resolve to the right binary.
if [[ -x "$HOME/go/bin/go" ]] && [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$HOME/go/bin:$PATH"
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
        err "Go not found. Install with: sudo apt install golang-go OR put a Go binary at \$HOME/go/bin/go"
        return 1
    fi
    log "Go $(go version | awk '{print $3}') (from $(command -v go))"
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
    if ! go build -o bin/vulture ./cmd/vulture/; then
        err "Backend build FAILED"
        return 1
    fi
    ok "Backend binary: backend/bin/vulture"
}

# ---------------------------------------------------------------------------
# Build: Go CLI
# ---------------------------------------------------------------------------

build_cli() {
    log "Building Go CLI..."
    check_go || return 1
    cd "$PROJECT_ROOT/cli"
    if ! go build -o bin/vulture ./; then
        err "CLI build FAILED"
        return 1
    fi
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

    # Install shared library first (all agents depend on it)
    log "  Installing shared library..."
    cd "$PROJECT_ROOT/agents/shared"
    "$py" -m pip install -e . --quiet 2>&1 | tail -1 || true
    ok "  shared library installed"

    # Auto-discover agents from the filesystem. Any agents/<name>/pyproject.toml
    # is treated as an installable agent (shared handled separately above).
    # This prevents the hardcoded-list drift we hit when adding agent-asvs.
    local installed=0
    local skipped=0
    while IFS= read -r -d '' agent_dir; do
        local agent_name
        agent_name=$(basename "$agent_dir")
        [[ "$agent_name" == "shared" ]] && continue
        log "  Installing $agent_name agent..."
        cd "$agent_dir"
        "$py" -m pip install -e . --quiet 2>&1 | tail -1 || true
        ok "  $agent_name agent installed"
        installed=$((installed + 1))
    done < <(find "$PROJECT_ROOT/agents" -mindepth 1 -maxdepth 2 -name "pyproject.toml" \
             -not -path "*/node_modules/*" -printf '%h\0' | sort -z)

    ok "All $installed agents installed ($skipped skipped)"
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
