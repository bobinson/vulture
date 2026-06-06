#!/usr/bin/env bash
# Fabricate an OFFLINE install fixture (tarball + SHA256SUMS + empty .sig) so the
# cross-distro e2e needs no real GitHub release / cosign / Go binary.
#
# Usage: build-fixture-tarball.sh <variant> <out.tar.gz>
#   variant: cli-only      | empty requirements-frozen.txt  (CLI-only build)
#            agents-hashed  | small REAL hashed lockfile     (system-Python happy path)
#            agents-hashless| non-empty UNHASHED manifest    (fail-closed)
#
# Companions are written at the tarball's stem (install.sh offline contract):
#   <stem>.SHA256SUMS  and  <stem>.sig (empty; use with VULTURE_ALLOW_UNSIGNED=true)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
VARIANT=${1:?variant required}
OUT=${2:?out.tar.gz required}
VERSION=${VERSION:-v0.1.0}

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/bin" "$STAGE/runtime/python/bin" "$STAGE/runtime/agents/shared"
install -m 0755 "$HERE/vulture-stub.sh" "$STAGE/bin/vulture"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"
printf 'PBS not bundled in this build (feature 0055 Tier B).\n' > "$STAGE/runtime/python/PBS_NOT_BUNDLED"
# A token first-party agent module (loaded via PYTHONPATH, never pip-installed).
printf '"""vulture-shared (stub for installer e2e)."""\n' > "$STAGE/runtime/agents/shared/__init__.py"

REQS="$STAGE/runtime/agents/requirements-frozen.txt"
case "$VARIANT" in
    cli-only)        : > "$REQS" ;;                                  # empty -> CLI-only
    agents-hashed)   cp "$HERE/fixtures/requirements-small.txt" "$REQS" ;;
    agents-hashless) printf 'pathspec>=0.12.0\nsniffio>=1.3.0\n' > "$REQS" ;;
    *) echo "unknown variant: $VARIANT" >&2; exit 2 ;;
esac

# Reproducible tarball (mirrors build-release.sh flags).
( cd "$STAGE" && tar --sort=name --mtime='2020-01-01 00:00:00Z' \
    --owner=0 --group=0 --numeric-owner -cf - . | gzip -9n > "$OUT" )

STEM="${OUT%.tar.gz}"
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$STEM.SHA256SUMS" )
: > "$STEM.sig"   # empty signature; accepted with VULTURE_ALLOW_UNSIGNED=true

echo "built $VARIANT fixture: $OUT (+ .SHA256SUMS, .sig)"
