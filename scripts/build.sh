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

check_node() {
    if ! command -v node &>/dev/null; then
        err "Node.js not found. Install with: sudo apt install nodejs npm"
        return 1
    fi
    log "Node $(node --version)"
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

# The agents venv holds exactly the hashed lockfile, agents/requirements-frozen.txt
# (the set the release ships), with every agents/<name>/ holding a pyproject.toml
# loaded from the checkout. scripts/locked-venv.sh builds it; its header says why
# nothing else is installed.
build_agents() {
    log "Building Python agents..."
    local venv_dir="$PROJECT_ROOT/agents/.venv" f
    local args=("$venv_dir" "$PROJECT_ROOT/agents/requirements-frozen.txt")
    for f in "$PROJECT_ROOT"/agents/*/pyproject.toml; do
        args+=("${f%/pyproject.toml}")
    done
    "$SCRIPT_DIR/locked-venv.sh" "${args[@]}" || return 1

    # The launcher invokes `python -m uvicorn ...`. A venv that matches the
    # lockfile but cannot import it was damaged since it was built: rebuild it.
    if ! "$venv_dir/bin/python" -c "import uvicorn" 2>/dev/null; then
        warn "  uvicorn does not import from the venv; rebuilding it"
        "$SCRIPT_DIR/locked-venv.sh" --force "${args[@]}" || return 1
    fi
    if ! "$venv_dir/bin/python" -c "import uvicorn" 2>/dev/null; then
        err "  uvicorn missing from venv after install — aborting"
        return 1
    fi
    ok "Agents venv built from the hashed lockfile"
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
            backend)  build_backend  || failed=$((failed + 1)) ;;
            cli)      build_cli      || failed=$((failed + 1)) ;;
            agents)   build_agents   || failed=$((failed + 1)) ;;
            frontend) build_frontend || failed=$((failed + 1)) ;;
            *)
                err "Unknown component: $component"
                err "Valid components: backend, cli, agents, frontend"
                failed=$((failed + 1))
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
