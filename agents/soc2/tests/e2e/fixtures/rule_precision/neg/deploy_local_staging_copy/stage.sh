#!/bin/sh
set -eu
STAGE="$1"
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$STAGE/runtime/agents"
for agent in shared worker; do
    rsync -a --exclude='__pycache__' --exclude='.venv' --exclude='*.egg-info' \
        "$REPO_ROOT/agents/$agent" "$STAGE/runtime/agents/"
done

for d in "$REPO_ROOT"/plugins/*/; do
    name=$(basename "$d")
    mkdir -p "$STAGE/runtime/plugins/$name"
    rsync -a --exclude='__pycache__' "$d/src" "$STAGE/runtime/plugins/$name/"
done
