#!/usr/bin/env bash
# Build a fresh <distro> image + offline fixture for <scenario>, run install.sh
# inside it, and assert the outcome (via runner.sh). Exits 0 (pass) / 1 (fail).
#
# Usage: run-one.sh <ubuntu|fedora> <scenario>
#   scenarios: no-python | py-no-optin | py-optin-hashed | py-optin-hashless | py-no-venv
#
# Scenarios that don't pull deps run with --network none (proving zero egress
# from install.sh); py-optin-hashed runs with network (the venv pip needs PyPI).
set -euo pipefail

DISTRO=${1:?distro (ubuntu|fedora)}
SCENARIO=${2:?scenario}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)

case "$SCENARIO" in
    no-python)        WITH_PY=0; WITH_VENV=0; VARIANT=cli-only;       NET=none ;;
    py-no-optin)      WITH_PY=1; WITH_VENV=1; VARIANT=cli-only;       NET=none ;;
    py-optin-hashed)  WITH_PY=1; WITH_VENV=1; VARIANT=agents-hashed;  NET=default ;;
    py-optin-hashless)WITH_PY=1; WITH_VENV=1; VARIANT=agents-hashless;NET=none ;;
    py-no-venv)       WITH_PY=1; WITH_VENV=0; VARIANT=agents-hashed;  NET=none ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac
# py-no-venv is Ubuntu-only (Fedora bundles venv with python3), so skip it there.
if [ "$SCENARIO" = py-no-venv ] && [ "$DISTRO" = fedora ]; then
    echo "SKIP [$DISTRO/$SCENARIO] Fedora bundles venv with python3 — N/A"; exit 0
fi

TAG="vulture-itest:${DISTRO}-py${WITH_PY}venv${WITH_VENV}"
FIX=$(mktemp -d); trap 'rm -rf "$FIX"' EXIT

echo "==> [$DISTRO/$SCENARIO] build fixture ($VARIANT)"
"$HERE/build-fixture-tarball.sh" "$VARIANT" "$FIX/vulture.tar.gz" >/dev/null
# The container's non-root user may have a different uid than the host (e.g.
# ubuntu:24.04 ships a uid-1000 'ubuntu' user, so 'tester' becomes 1001). The
# mktemp dir is mode 700, so make the fixtures world-readable for the mount.
chmod -R a+rX "$FIX"

echo "==> [$DISTRO/$SCENARIO] build image $TAG"
docker build -q \
    --build-arg "WITH_PY=$WITH_PY" --build-arg "WITH_VENV=$WITH_VENV" \
    -f "$HERE/Dockerfile.$DISTRO" -t "$TAG" "$HERE" >/dev/null

NETARG=""; [ "$NET" = none ] && NETARG="--network=none"
echo "==> [$DISTRO/$SCENARIO] run install.sh (net=$NET)"
docker run --rm $NETARG \
    -v "$REPO":/repo:ro -v "$FIX":/fix:ro \
    -e "SCENARIO=$SCENARIO" \
    "$TAG" sh /repo/scripts/tests/docker/runner.sh
