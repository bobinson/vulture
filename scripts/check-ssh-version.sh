#!/usr/bin/env sh
# check-ssh-version.sh — assert OpenSSH >= MIN (default 7.6), the version that
# StrictHostKeyChecking=accept-new requires (feature 0065 §L2). A base-image
# downgrade below this silently degrades git-over-SSH host-key verification, so
# CI asserts it against the shipped backend image.
#
# Version source, in order: a banner piped on stdin, else `ssh -V` on PATH.
# Usage:
#   scripts/check-ssh-version.sh [MIN]                       # MIN like 7.6
#   ssh -V 2>&1 | scripts/check-ssh-version.sh
#   docker compose run --rm --no-deps --entrypoint ssh backend -V 2>&1 \
#     | scripts/check-ssh-version.sh
set -u

MIN="${1:-7.6}"
min_major=${MIN%%.*}
min_minor=${MIN#*.}
# No dot in MIN (e.g. "8") -> treat minor as 0.
case "$min_minor" in "$MIN") min_minor=0 ;; esac

# Prefer a piped banner (CI pipes the image's `ssh -V`); else probe PATH.
if [ ! -t 0 ]; then
    banner=$(cat)
else
    banner=$(ssh -V 2>&1 || true)
fi

ver=$(printf '%s\n' "$banner" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1)
if [ -z "$ver" ]; then
    echo "check-ssh-version: could not parse an OpenSSH version from: ${banner:-<empty>}" >&2
    exit 1
fi
major=${ver%%.*}
minor=${ver#*.}

if [ "$major" -gt "$min_major" ] || { [ "$major" -eq "$min_major" ] && [ "$minor" -ge "$min_minor" ]; }; then
    echo "check-ssh-version: OpenSSH $ver >= $MIN OK"
    exit 0
fi

echo "check-ssh-version: OpenSSH $ver < $MIN — StrictHostKeyChecking=accept-new (0065) needs >= $MIN. Upgrade the base image, or ship a pre-populated VULTURE_GIT_SSH_KNOWN_HOSTS with VULTURE_GIT_SSH_STRICT=yes." >&2
exit 1
