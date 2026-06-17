#!/usr/bin/env bash
#
# scripts/tests/docker/pbs-bundle-smoke.sh — Tier B (bundled python-build-
# standalone) e2e (feature 0055 / bug 0002).
#
# Modeled on plugin-smoke.sh. PROVES that a native install runs the Python
# agents with NO system Python and NO Docker, using a BUNDLED CPython 3.12
# interpreter (python-build-standalone) shipped INSIDE the release tarball.
#
# The container base is a BARE distro with NO python3 installed (ubuntu:24.04
# / fedora:41 both ship no python3). So if `vulture start` brings agents up,
# they MUST be running on the bundled interpreter — there is no other Python.
#
# It installs the release tarball OFFLINE (VULTURE_OFFLINE_TARBALL +
# VULTURE_VERSION + VULTURE_ALLOW_UNSIGNED), starts the install-mode launcher
# (`vulture start --foreground`, which serves API + embedded SPA on :28080),
# and asserts:
#
#   (a) $VULTURE_HOME/runtime/python/bin/python3.12 EXISTS and RUNS, importing
#       sys + uvicorn + fastapi (the agent deps are pre-installed at build).
#   (b) `vulture start --foreground &` brings the backend up on
#       127.0.0.1:28080 AND at least one agent /health returns 200 — i.e. the
#       agents ran on the bundled python (the only python present).
#   (c) `vulture doctor` python check is OK (exit not 1).
#
# Usage: pbs-bundle-smoke.sh <ubuntu|fedora> [real-tarball.tar.gz]
#   Defaults to dist/vulture-v0.0.4-linux-amd64.tar.gz.
#
# Exits 0 (PASS) / non-zero (FAIL). Requires Docker. The install runs OFFLINE
# (--network none): a BUNDLED tarball needs zero egress; an agent /health that
# comes up with no network proves the deps were pre-installed at build time.
# This script is shellcheck-clean.
set -euo pipefail

DISTRO=${1:?distro (ubuntu|fedora)}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TARBALL=${2:-$REPO/dist/vulture-v0.0.4-linux-amd64.tar.gz}
[ -f "$TARBALL" ] || { echo "FAIL [pbs] tarball not found: $TARBALL" >&2; exit 1; }

case "$DISTRO" in
    ubuntu) IMAGE=ubuntu:24.04 ;;
    fedora) IMAGE=fedora:41 ;;
    *) echo "FAIL [pbs] unknown distro: $DISTRO (want ubuntu|fedora)" >&2; exit 2 ;;
esac

FIXDIR=$(cd "$(dirname "$TARBALL")" && pwd)
TARNAME=$(basename "$TARBALL")
# Derive the version install.sh expects from the tarball name:
# vulture-<version>-<os>-<arch>.tar.gz
VER=$(printf '%s' "$TARNAME" | sed -E 's/^vulture-(.*)-(linux|darwin)-(amd64|arm64)\.tar\.gz$/\1/')

echo "==> [pbs/$DISTRO] OFFLINE install bundled tarball ($TARNAME, ver=$VER); prove agents run on bundled python3.12"
docker run --rm --network none \
    -v "$FIXDIR":/fix:ro -v "$REPO":/repo:ro \
    -e "TARNAME=$TARNAME" -e "VER=$VER" \
    "$IMAGE" sh -euc '
    # (pre) BARE host invariant: this distro must ship NO python3. If a python3
    # leaks onto PATH the whole test is meaningless (agents could use it), so
    # fail loudly rather than pass for the wrong reason.
    if command -v python3 >/dev/null 2>&1; then
        echo "FAIL [pbs] host has python3 on PATH ($(command -v python3)); not a bare host" >&2
        exit 1
    fi

    # Writable copy + offline companion fixtures (empty .sig OK w/ ALLOW_UNSIGNED).
    mkdir -p /work && cp "/fix/$TARNAME" /work/
    ( cd /work && sha256sum "$TARNAME" > SHA256SUMS && : > "${TARNAME%.tar.gz}.sig" )

    export VULTURE_HOME=/root/.vulture
    export VULTURE_OFFLINE_TARBALL="/work/$TARNAME"
    export VULTURE_VERSION="$VER"          # skip the GitHub releases API
    export VULTURE_ALLOW_UNSIGNED=true
    export VULTURE_NO_UPDATE_CHECK=true
    # NOTE: VULTURE_USE_SYSTEM_PYTHON is left UNSET. A bundled interpreter must
    # be detected on its own; we never opt into system python (there is none).

    sh /repo/install.sh >/tmp/install.log 2>&1 \
        || { echo "FAIL [pbs] install.sh failed:"; cat /tmp/install.log; exit 1; }

    PYBIN="$VULTURE_HOME/runtime/python/bin/python3.12"

    # --- (a) bundled interpreter exists + runs + imports the agent stack ---
    if [ ! -x "$PYBIN" ]; then
        echo "FAIL [pbs] bundled interpreter missing/not-executable: $PYBIN" >&2
        ls -la "$VULTURE_HOME/runtime/python/bin" 2>/dev/null >&2 || true
        exit 1
    fi
    if ! "$PYBIN" -c "import sys, uvicorn, fastapi; print(sys.version)" >/tmp/pyver.log 2>&1; then
        echo "FAIL [pbs] bundled python could not import sys/uvicorn/fastapi:" >&2
        cat /tmp/pyver.log >&2
        exit 1
    fi
    echo "PBS interpreter OK: $(cat /tmp/pyver.log)"

    # --- (b) install-mode launcher: backend up + >=1 agent /health == 200 ---
    set -a; . "$VULTURE_HOME/config/.env"; set +a

    "$VULTURE_HOME/bin/vulture" start --foreground >/tmp/serve.log 2>&1 &
    SV=$!

    up=0
    for _ in $(seq 1 60); do
        if curl -sf -o /dev/null "http://127.0.0.1:28080/api/agents" 2>/dev/null; then up=1; break; fi
        # curl may be absent on a bare offline host; fall back to the bundled
        # python for the probe so we never depend on system tooling.
        if "$PYBIN" - <<PY 2>/dev/null
import urllib.request, sys
try:
    urllib.request.urlopen("http://127.0.0.1:28080/api/agents", timeout=1).read()
except Exception:
    sys.exit(1)
PY
        then up=1; break; fi
        sleep 0.5
    done
    if [ "$up" != 1 ]; then
        echo "FAIL [pbs] backend never came up on :28080" >&2
        cat /tmp/serve.log >&2
        kill "$SV" 2>/dev/null || true
        exit 1
    fi

    # Poll /api/agents until at least one agent reports a healthy/running state.
    # Agents spawn after the backend binds, so allow a generous window. Uses the
    # bundled python for the HTTP GET + JSON parse (no jq/curl dependency).
    healthy=0
    for _ in $(seq 1 60); do
        if "$PYBIN" - <<PY
import json, urllib.request, sys
try:
    raw = urllib.request.urlopen("http://127.0.0.1:28080/api/agents", timeout=2).read()
    data = json.loads(raw)
except Exception:
    sys.exit(1)
agents = data.get("agents", data) if isinstance(data, dict) else data
ok = False
for a in (agents or []):
    s = str(a.get("status", a.get("health", ""))).lower()
    if a.get("healthy") is True or s in ("ok", "healthy", "running", "available", "up"):
        ok = True
        break
sys.exit(0 if ok else 1)
PY
        then healthy=1; break; fi
        sleep 1
    done
    kill "$SV" 2>/dev/null || true
    if [ "$healthy" != 1 ]; then
        echo "FAIL [pbs] no agent reported healthy on :28080 (agents did not run on bundled python)" >&2
        cat /tmp/serve.log >&2
        exit 1
    fi
    echo "PBS agents OK: backend up + >=1 agent healthy on bundled python3.12"

    # --- (c) vulture doctor python check OK (exit not 1) ---
    set +e
    "$VULTURE_HOME/bin/vulture" doctor >/tmp/doctor.log 2>&1
    DRC=$?
    set -e
    if [ "$DRC" = 1 ]; then
        echo "FAIL [pbs] vulture doctor exited 1 (a check FAILED):" >&2
        cat /tmp/doctor.log >&2
        exit 1
    fi
    if ! grep -Eq "\[OK\].*[Pp]ython" /tmp/doctor.log; then
        echo "FAIL [pbs] doctor did not report python runtime [OK]:" >&2
        cat /tmp/doctor.log >&2
        exit 1
    fi
    echo "PBS doctor OK: python runtime check [OK] (exit $DRC)"

    echo "PBS OK: bundled python3.12 present, agents ran on it offline, doctor OK"
'
echo "PASS [pbs/$DISTRO] bundled python-build-standalone runs agents with no system Python"
