#!/usr/bin/env bash
set -euo pipefail

HOST="$1"
ssh -o StrictHostKeyChecking=no -i "$HOME/.ssh/deploy" "deploy@$HOST" 'systemctl restart app'
