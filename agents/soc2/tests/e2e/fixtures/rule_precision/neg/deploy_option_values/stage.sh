#!/bin/sh
set -eu
rsync -a --chown=www-data:www-data dist/ out/
rsync -a --chmod=D755,F644 --usermap=build:www dist/ public/
