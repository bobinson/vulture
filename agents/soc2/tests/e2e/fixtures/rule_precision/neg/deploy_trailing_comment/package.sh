#!/bin/sh
set -eu
npm run build
cp -R dist/ out/  # rsync out/ to ops@prod:/srv afterwards, from the release host
