#!/bin/sh
set -eu
rsync -a dist/ rsync://mirror.example.org/site/
rsync -a dist/ mirror.example.org::site
rsync -az -e ssh dist/ "$TARGET"
