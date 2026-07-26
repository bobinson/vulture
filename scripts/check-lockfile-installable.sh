#!/usr/bin/env bash
#
# scripts/check-lockfile-installable.sh — release-installability gate.
#
# Verifies the hashed agent lockfile (agents/requirements-frozen.txt) ACTUALLY
# installs — with the SAME `--only-binary :all:` the release build uses
# (scripts/build-release.sh) — on EVERY release target platform, checked
# cross-platform from a single host via `uv pip install --python-platform`.
#
# WHY THIS EXISTS (learned the hard way):
#   gen-lockfile.sh resolves `--universal`, where an sdist satisfies the
#   resolver, so a package that ships wheels for only SOME platforms passes the
#   freshness gate and then breaks a real build. Concrete case: litellm 1.93.0
#   ships manylinux-only wheels + an sdist — no macOS wheel — so the darwin
#   `--only-binary` release build fails with "No matching distribution".
#   scripts/check-lockfile.sh checks REPRODUCIBILITY; THIS checks INSTALLABILITY.
#
# Hits real PyPI (no --exclude-newer) — a "for real" check, not a resolver echo.
# Never mutates the tree. Run by scripts/release-preflight.sh (vulture.sh
# release) and safe to run in CI.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/agents/requirements-frozen.txt"

# The four release triples built by .github/workflows/release.yml, as uv
# --python-platform targets. KEEP IN SYNC with the release matrix.
TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-apple-darwin
    aarch64-apple-darwin
)
PYVER=3.12  # the CPython the release bundles (python-build-standalone); litellm pins <3.14

if ! grep -q -- '--hash=' "$LOCK" 2>/dev/null; then
    echo "check-lockfile-installable: no hashed lockfile at $LOCK — CLI-only build, nothing to verify"
    exit 0
fi
if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv not found — required to verify lockfile installability" >&2
    exit 1
fi

VENV=$(mktemp -d)
trap 'rm -rf "$VENV"' EXIT
uv venv "$VENV/v" --python "$PYVER" >/dev/null 2>&1 \
    || { echo "error: could not create python $PYVER venv (uv venv)" >&2; exit 1; }

rc=0
for plat in "${TARGETS[@]}"; do
    if uv pip install --python "$VENV/v/bin/python" --dry-run \
           --require-hashes --only-binary :all: --python-platform "$plat" \
           -r "$LOCK" >/dev/null 2>&1; then
        echo "  ok:   $plat"
    else
        echo "  FAIL: $plat — a pinned package has no installable wheel for this target" >&2
        # Re-run visibly to surface the offending package(s).
        uv pip install --python "$VENV/v/bin/python" --dry-run \
            --require-hashes --only-binary :all: --python-platform "$plat" \
            -r "$LOCK" 2>&1 | grep -iE 'no usable wheels|has no|because' | head -3 | sed 's/^/        /' >&2 || true
        rc=1
    fi
done

if [ "$rc" -ne 0 ]; then
    echo "error: lockfile is NOT installable on all release targets (see above)." >&2
    echo "       a package resolves universally (its sdist satisfies the resolver) but ships" >&2
    echo "       no wheel for a target platform. Pin it to a version WITH wheels for every" >&2
    echo "       target (or add a marker split in agents/lockfile-constraints.txt), then" >&2
    echo "       re-run 'make freeze-deps' and commit." >&2
    exit 1
fi
echo "check-lockfile-installable: OK — all ${#TARGETS[@]} release targets installable (--only-binary, real PyPI)"
