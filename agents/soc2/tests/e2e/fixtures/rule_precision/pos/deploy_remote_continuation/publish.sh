#!/bin/sh
set -eu
npm run build
rsync -avz --delete \
    --exclude='*.map' \
    build/ "$DEPLOY_HOST:/srv/app/"
