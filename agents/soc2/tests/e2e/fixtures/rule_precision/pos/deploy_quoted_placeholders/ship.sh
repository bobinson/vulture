#!/bin/sh
set -eu
HOST="$1"
USER="$2"
rsync -avz dist/ "$HOST":/srv/app
scp app.tar "$USER"@"$HOST":/srv
