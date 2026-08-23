#!/usr/bin/env bash
set -euo pipefail

HOST="$1"
ssh -o StrictHostKeyChecking=accept-new -i "$HOME/.ssh/deploy" "deploy@$HOST" 'systemctl restart app'
