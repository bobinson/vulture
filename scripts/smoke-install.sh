#!/usr/bin/env bash
#
# scripts/smoke-install.sh — end-to-end happy-path test for the
# native installer (feature 0044). Used by CI and by developers
# verifying install.sh changes locally.
#
# Usage:
#   scripts/smoke-install.sh <tarball.tar.gz>
#
# What it asserts:
#   - install.sh completes without sudo
#   - vulture binary is reachable from ~/.local/bin
#   - vulture version exits 0
#   - vulture doctor --no-update-check is not FAIL
#   - the daemon starts, serves /health, and a REAL `vulture scan` of a tiny
#     fixture reaches a terminal 'completed' status — proving the audit pipeline
#     runs end-to-end (item #3). When agents are present (bundled python or a
#     system-python build) it additionally asserts findings > 0; on a lean,
#     agent-less tarball it degrades gracefully with a clear message.
#   - vulture uninstall --yes leaves no residue
#
# Run from a clean machine (CI runner or a containerized smoke env).

set -euo pipefail

TARBALL=${1:-}
if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "usage: $0 <vulture-*.tar.gz>" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$REPO_ROOT/scripts/lib/hash.sh"
SMOKE_HOME=$(mktemp -d)/vulture-smoke
SMOKE_HOME_REAL=$(readlink -f "$SMOKE_HOME" 2>/dev/null || echo "$SMOKE_HOME")
TARBALL_REAL=$(readlink -f "$TARBALL" 2>/dev/null || echo "$TARBALL")

# Work on an isolated COPY of the tarball: the offline-install path writes
# companion fixtures (SHA256SUMS + an empty .sig) next to it, and we must NOT
# pollute the tarball's source dir — in CI that dir is dist/, which is uploaded
# verbatim as the release assets (an empty .sig there breaks the GH upload).
SMOKE_WORK=$(mktemp -d)
cp "$TARBALL_REAL" "$SMOKE_WORK/"
OFFLINE_TARBALL="$SMOKE_WORK/$(basename "$TARBALL_REAL")"

echo "==> smoke install into $SMOKE_HOME"

# Use the offline-tarball path so we don't need a real GH release.
export VULTURE_HOME="$SMOKE_HOME_REAL"
export VULTURE_OFFLINE_TARBALL="$OFFLINE_TARBALL"
export VULTURE_NO_UPDATE_CHECK=true
export VULTURE_ALLOW_UNSIGNED=true   # local builds aren't cosign-signed
# Disable the SYSTEM-Python agent path so a LEAN (PBS_NOT_BUNDLED) tarball stays
# deterministic: with AUTO detect (the default), a runner that happens to have
# Python 3.12/3.13 would pull the entire hash-pinned agent closure (~80 PyPI
# wheels) on every release build × platform, making releases slow and PyPI-flaky.
# That system-Python install path is covered by the docker e2e matrix
# (scripts/tests/docker) on controlled interpreters.
#
# NOTE: this does NOT force CLI-only for a BUNDLED tarball. install.sh checks for
# a bundled runtime/python interpreter BEFORE consulting VULTURE_USE_SYSTEM_PYTHON
# (see install_python_deps), so a VULTURE_BUNDLE_PBS=1 tarball runs its agents
# from the bundled interpreter regardless of this flag. The bundled-vs-lean split
# below uses the PBS marker to decide whether agents (and findings>0) are REQUIRED.
export VULTURE_USE_SYSTEM_PYTHON=0

# Prepare offline-companion fixtures beside the COPY (never the source dir).
SHASUM_PATH=${OFFLINE_TARBALL%.tar.gz}.SHA256SUMS
TARBALL_NAME=$(basename "$OFFLINE_TARBALL")
SUM=$(sha256_of "$OFFLINE_TARBALL")
printf '%s  %s\n' "$SUM" "$TARBALL_NAME" > "$SHASUM_PATH"
: > "${OFFLINE_TARBALL%.tar.gz}.sig"   # empty sig OK with ALLOW_UNSIGNED

# Run installer. Note: we run a shell-piped invocation rather than
# bash -x so we can see real failure paths.
echo "==> running install.sh"
sh "$REPO_ROOT/install.sh" || { echo "FAIL: install.sh exited non-zero"; exit 1; }

# Assert binary is reachable at the documented path.
BIN="$SMOKE_HOME_REAL/bin/vulture"
if [ ! -x "$BIN" ]; then
    echo "FAIL: $BIN is not executable"; exit 1
fi

# Assert VERSION file exists.
if [ ! -f "$SMOKE_HOME_REAL/VERSION" ]; then
    echo "FAIL: VERSION file missing"; exit 1
fi

# Assert config/.env exists with mode 0600 and a real JWT secret.
ENVFILE="$SMOKE_HOME_REAL/config/.env"
[ -f "$ENVFILE" ] || { echo "FAIL: config/.env missing"; exit 1; }
MODE=$(stat -c '%a' "$ENVFILE" 2>/dev/null || stat -f '%Lp' "$ENVFILE" 2>/dev/null)
if [ "$MODE" != "600" ]; then
    echo "FAIL: config/.env mode = $MODE, want 600"; exit 1
fi
if ! grep -qE '^VULTURE_JWT_SECRET=[a-f0-9]{64}$' "$ENVFILE"; then
    echo "FAIL: VULTURE_JWT_SECRET is not 64 hex chars"; exit 1
fi

# Smoke: vulture version
"$BIN" version | grep -q "vulture" || { echo "FAIL: vulture version output"; exit 1; }

# Doctor (in install mode VULTURE_HOME is set above so DetectMode finds it).
# Local builds may omit python-build-standalone — accept FAIL on the
# python check if PBS_NOT_BUNDLED marker is present.
set +e
"$BIN" doctor --no-update-check
DOCTOR_RC=$?
set -e
PBS_MARKER="$SMOKE_HOME_REAL/runtime/python/PBS_NOT_BUNDLED"
if [ "$DOCTOR_RC" -ne 0 ] && [ "$DOCTOR_RC" -ne 2 ]; then
    if [ -f "$PBS_MARKER" ]; then
        echo "    (local build without PBS — doctor FAIL on python is expected)"
    else
        echo "FAIL: doctor exit = $DOCTOR_RC (want 0 or 2/WARN)"; exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Real-scan smoke (item #3): start the daemon, wait for /health, run an actual
# `vulture scan` over a tiny fixture, and assert the audit reached a terminal
# 'completed' status (proof the pipeline executed, not merely that it installs).
# Each step is a tiny single-purpose function (cyclomatic < 5), POSIX sh only.
# ---------------------------------------------------------------------------

# Resolve the daemon's loopback API base from the installer-written .env so a
# config.ini port override is honoured (defaults to 28080 — see install.sh).
PORT=$(sed -n 's/^VULTURE_PORT=\([0-9][0-9]*\)$/\1/p' "$ENVFILE" 2>/dev/null)
[ -n "$PORT" ] || PORT=28080
API="http://127.0.0.1:$PORT"
DAEMON_PID=""

# All HTTP probes share one bounded curl invocation so no step can hang CI if
# a connection is held open (DRY; --max-time caps every request).
api_get() {
    curl -fsS --max-time 30 "$API/$1" 2>/dev/null
}

# health_up — true (0) once GET $API/health answers, else false.
health_up() {
    api_get health >/dev/null
}

# agents_up — true (0) when at least one audit agent reports "healthy" at the
# local API (GET /api/agents sets status=healthy only when the agent's /health
# returns 200). A lean (agent-less) tarball never satisfies this, which is how
# we decide whether findings>0 is required or we degrade gracefully.
agents_up() {
    api_get api/agents | grep -q '"status":"healthy"'
}

# wait_for <predicate> [max_tries] — poll <predicate> every 0.5s up to max_tries
# (default 60 ≈ 30s); return 0 on success, 1 on timeout.
wait_for() {
    _tries=${2:-60}
    i=0
    while [ "$i" -lt "$_tries" ]; do
        if "$1"; then return 0; fi
        i=$((i + 1))
        sleep 0.5
    done
    return 1
}

# stop_daemon — best-effort SIGTERM of the backgrounded daemon (idempotent).
stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}
# Never leave the daemon running if a later assertion exits the script.
trap stop_daemon EXIT INT TERM

# make_fixture — write a tiny target with obvious, skill-detectable issues so a
# scan with agents present yields findings>0. Echoes the fixture dir path.
make_fixture() {
    _dir="$SMOKE_WORK/scan-fixture"
    mkdir -p "$_dir"
    cat > "$_dir/vuln.py" <<'PY'
import hashlib, subprocess

password = "hunter2"  # hardcoded credential


def weak_digest(data):
    return hashlib.md5(data).hexdigest()  # weak hash


def run(cmd):
    return subprocess.call(cmd, shell=True)  # shell injection
PY
    echo "$_dir"
}

# scan_submit — run `vulture scan <target>` against the running daemon and echo
# the created Audit ID parsed from its output. The submit goes to the live API.
scan_submit() {
    _out=$("$BIN" scan "$1" 2>&1)
    echo "$_out" >&2
    echo "$_out" | sed -n 's/^Audit ID: \([0-9a-f]*\).*/\1/p' | tail -n1
}

# audit_field — extract a scalar field from GET /api/audits/<id>. Takes the
# FIRST "<key>":<value> occurrence: the audit's top-level "status"/"findings_count"
# is serialized BEFORE the findings[] array (model.Audit field order), so the
# first match is the audit's — NOT a finding's nested validation "status"
# (e.g. "suspicious", which is a finding validation status, never an audit one).
# Value may be quoted or a bare number. Binary/version-independent (older bundled
# CLIs omit the "Status:" summary line).
audit_field() {
    api_get "api/audits/$1" \
        | grep -oE "\"$2\":[[:space:]]*\"?[A-Za-z0-9_]+" | head -n1 \
        | sed -E "s/.*\"$2\":[[:space:]]*\"?//"
}

# drive_audit — open the audit's SSE stream, which is what kicks off the run on
# the backend, and drain it to EOF (the stream closes when the run completes).
# Bounded by --max-time so a held-open connection can never hang the suite.
drive_audit() {
    curl -fsS -N --max-time 120 "$API/api/audits/$1/stream" >/dev/null 2>&1 || true
}

echo "==> starting daemon for real-scan smoke"
"$BIN" start --foreground > "$SMOKE_WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
if ! wait_for health_up; then
    echo "FAIL: daemon /health never came up at $API"; cat "$SMOKE_WORK/daemon.log"; exit 1
fi
echo "    daemon healthy at $API"

# is_bundled — true (0) when this tarball BUNDLES a python-build-standalone
# runtime: the PBS_NOT_BUNDLED marker is ABSENT and runtime/python/bin/python3.12
# is executable. A bundled tarball runs the Python agents from its own
# interpreter (install.sh prefers it over VULTURE_USE_SYSTEM_PYTHON), so agents
# MUST come up and a real scan MUST surface findings. A lean tarball trips the
# marker and is allowed to degrade to 0 findings.
is_bundled() {
    [ ! -f "$SMOKE_HOME_REAL/runtime/python/PBS_NOT_BUNDLED" ] \
        && [ -x "$SMOKE_HOME_REAL/runtime/python/bin/python3.12" ]
}

# Decide the contract up front: a BUNDLED tarball REQUIRES agents (generous
# timeout — the bundled interpreter + agent imports take longer to warm up than
# a lean build's brief probe); a LEAN tarball never brings agents up, so keep
# its probe short and don't pay a long timeout on every lean build.
HAVE_AGENTS=0
if is_bundled; then
    BUNDLED=1
    echo "    bundled python runtime detected — agents REQUIRED, findings>0 will be asserted"
    if wait_for agents_up 120; then   # ~60s: bundled agents warm up slower
        HAVE_AGENTS=1
    else
        echo "FAIL: bundled tarball but no agent reported healthy within ~60s at $API"
        cat "$SMOKE_WORK/daemon.log"; exit 1
    fi
else
    BUNDLED=0
    echo "    lean tarball (PBS_NOT_BUNDLED) — agents optional, 0 findings tolerated"
    if wait_for agents_up 20; then HAVE_AGENTS=1; fi
fi

FIXTURE=$(make_fixture)
echo "==> running vulture scan $FIXTURE"
export VULTURE_API_URL="$API"
AUDIT_ID=$(scan_submit "$FIXTURE")
if [ -z "$AUDIT_ID" ]; then
    echo "FAIL: vulture scan did not create an audit (no Audit ID in output)"; exit 1
fi
echo "    submitted audit $AUDIT_ID"

# Opening the stream is what triggers the run on the backend; drain it so the
# run completes regardless of the bundled CLI's own auto-run behaviour.
drive_audit "$AUDIT_ID"

# audit_done — terminal-status predicate for wait_for (completed or failed).
audit_done() {
    _s=$(audit_field "$AUDIT_ID" status)
    [ "$_s" = "completed" ] || [ "$_s" = "failed" ]
}
wait_for audit_done || true

SCAN_STATUS=$(audit_field "$AUDIT_ID" status)
SCAN_FINDINGS=$(audit_field "$AUDIT_ID" findings_count)
[ -n "$SCAN_FINDINGS" ] || SCAN_FINDINGS=0

# Assert the audit reached a terminal 'completed' status (the pipeline ran).
if [ "$SCAN_STATUS" != "completed" ]; then
    echo "FAIL: scan did not complete (status=$SCAN_STATUS, findings=$SCAN_FINDINGS)"
    cat "$SMOKE_WORK/daemon.log"; exit 1
fi

# A BUNDLED tarball MUST surface findings (its agents are required and ran over a
# fixture with obvious skill-detectable issues); fail LOUDLY otherwise so a
# broken/slow bundled agent set can never silently downgrade to the lean path.
# A LEAN tarball has no agents, so 0 findings is the expected, tolerated outcome.
if [ "$BUNDLED" = 1 ]; then
    if [ "$SCAN_FINDINGS" -lt 1 ]; then
        echo "FAIL: bundled tarball but scan produced 0 findings (agents broken or did not run)"
        cat "$SMOKE_WORK/daemon.log"; exit 1
    fi
    echo "    scan completed with $SCAN_FINDINGS findings (bundled agents ran)"
elif [ "$HAVE_AGENTS" = 1 ]; then
    # Lean tarball that nonetheless brought agents up (e.g. a future system-Python
    # smoke variant): still require findings since an agent demonstrably ran.
    if [ "$SCAN_FINDINGS" -lt 1 ]; then
        echo "FAIL: agents reachable but scan produced 0 findings"; exit 1
    fi
    echo "    scan completed with $SCAN_FINDINGS findings (agents ran)"
else
    echo "    scan completed; no agents in this (lean) tarball, so 0 findings is expected"
fi

stop_daemon

# Uninstall cleanly.
echo "==> running vulture uninstall --yes"
"$BIN" uninstall --yes || { echo "FAIL: uninstall non-zero"; exit 1; }
if [ -d "$SMOKE_HOME_REAL" ]; then
    echo "FAIL: $SMOKE_HOME_REAL still present after uninstall"; exit 1
fi

echo ""
echo "==> smoke install: PASS"
