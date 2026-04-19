#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: scripts/vulture.sh stop docker [--volumes|-v]

Options:
  --volumes, -v    Also remove PostgreSQL data volume (DESTROYS DATA)
  --help, -h       Show this help

Examples:
  scripts/vulture.sh stop docker              # Stop services, keep data
  scripts/vulture.sh stop docker --volumes    # Stop services and delete all data
EOF
    exit 0
}

REMOVE_VOLUMES=false

for arg in "$@"; do
    case "$arg" in
        --volumes|-v)
            REMOVE_VOLUMES=true
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Error: unknown option '$arg'"
            echo
            usage
            ;;
    esac
done

echo
echo "  Stopping Vulture Production..."
echo

if $REMOVE_VOLUMES; then
    echo "  Removing containers and volumes (data will be deleted)..."
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" down --volumes
else
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" down
fi

echo
echo "  Vulture Production stopped."
if $REMOVE_VOLUMES; then
    echo "  Volumes removed — PostgreSQL data has been deleted."
else
    echo "  Data volumes preserved. Use --volumes to remove them."
fi
echo
