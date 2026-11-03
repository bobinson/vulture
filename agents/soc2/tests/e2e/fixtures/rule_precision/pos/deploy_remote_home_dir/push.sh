#!/bin/sh
set -eu
npm run build
rsync -avz dist/ prod:
