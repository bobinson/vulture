#!/bin/sh
set -eu
apt-get update
apt-get install -y --no-install-recommends rsync openssh-client
command -v rsync >/dev/null
