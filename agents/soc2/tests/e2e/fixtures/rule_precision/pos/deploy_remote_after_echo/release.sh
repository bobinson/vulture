#!/bin/sh
set -eu
echo "publishing" && rsync -az dist/ ops@prod:/srv/app/
