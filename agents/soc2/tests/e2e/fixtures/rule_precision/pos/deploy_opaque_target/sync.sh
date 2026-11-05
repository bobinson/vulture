#!/bin/sh
set -eu
TARGET="$1"
rsync -az dist/ "$TARGET"
