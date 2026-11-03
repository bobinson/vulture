#!/bin/sh
set -eu
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
echo "Copy the widget scripts to the phone:"
echo "   scp $SCRIPT_DIR/quick-auth.sh phone:~/.shortcuts/QuickAuth"
printf '   rsync -a %s/ phone:~/.shortcuts/\n' "$SCRIPT_DIR"
