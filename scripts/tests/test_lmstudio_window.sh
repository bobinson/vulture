#!/usr/bin/env sh
# Tests for the dev-mode LM Studio loaded-window detector in start.sh (feature
# 0074, review item 38).
#
# The backend broker probes LM Studio's loaded window itself. The shell detector
# exported VULTURE_LLM_CTX_SIZE, which outranks that probe, and it also fell
# back to max_context_length (the advertised maximum, not the loaded window).
# So with the broker on, the shell must defer to the backend probe and export
# nothing. With --no-broker no probe runs, so the shell detector is the only
# one, and it must read loaded_context_length only (W3).
#
# A stub LM Studio listing is served on an ephemeral loopback port. start.sh
# reads the LM Studio URL from <root>/config.ini, so the script is copied into a
# throwaway root whose config.ini points at the stub. Nothing in the repo is
# written. VULTURE_LAUNCH_DRY_RUN=1 exits before anything boots.
#
# POSIX sh (CI runs `shellcheck scripts/tests/*.sh`); start.sh runs under bash.
# Run: scripts/tests/test_lmstudio_window.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START="$SCRIPT_DIR/../start.sh"
PASS=0
FAIL=0
TMP="$(mktemp -d)"
STUB_PIDS=""
STUB_ROOT=""

cleanup() {
    for pid in $STUB_PIDS; do kill "$pid" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
# An operator pin always wins in start.sh; the cases below test detection.
unset VULTURE_LLM_CTX_SIZE

if ! command -v python3 >/dev/null 2>&1; then
    echo "test_lmstudio_window: SKIP (python3 not available)"
    exit 0
fi

# start_stub <name> <listing-json>: serve the listing at /api/v0/models (and an
# empty OpenAI /v1/models) on an ephemeral port, and set STUB_ROOT to a root dir
# whose config.ini points start.sh at it. Not called through a command
# substitution: the background server would hold its pipe open forever.
start_stub() {
    name="$1"; listing="$2"; root="$TMP/$name"
    mkdir -p "$root/scripts"
    cp "$START" "$root/scripts/start.sh"
    printf '%s' "$listing" > "$root/listing.json"
    python3 - "$root/listing.json" "$root/port" >/dev/null 2>&1 <<'PY' &
import http.server, sys
body = open(sys.argv[1], "rb").read()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        out = body if self.path.startswith("/api/v0/models") else b'{"data":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY
    STUB_PIDS="$STUB_PIDS $!"
    i=0
    while [ ! -s "$root/port" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    printf '[lmstudio]\nurl = http://127.0.0.1:%s/v1\n' "$(cat "$root/port")" > "$root/config.ini"
    STUB_ROOT="$root"
}

run_dev() {
    root="$1"; shift
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null bash "$root/scripts/start.sh" "$@" 2>&1
}

assert_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [$label] expected: $needle"; echo "    output: $haystack"; FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    haystack="$1"; needle="$2"; label="$3"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        echo "  FAIL [$label] did NOT expect: $needle"; echo "    output: $haystack"; FAIL=$((FAIL + 1))
    else
        echo "  PASS [$label]"; PASS=$((PASS + 1))
    fi
}

echo "test_lmstudio_window:"

LOADED='{"data":[{"id":"qwen/qwen3-27b","type":"llm","state":"loaded","loaded_context_length":262144,"max_context_length":262144},{"id":"text-embedding-nomic","type":"embeddings","state":"loaded","loaded_context_length":2048}]}'
MAX_ONLY='{"data":[{"id":"qwen/qwen3-27b","type":"llm","state":"not-loaded","max_context_length":131072}]}'

start_stub loaded "$LOADED"; loaded_root="$STUB_ROOT"
start_stub maxonly "$MAX_ONLY"; max_root="$STUB_ROOT"

# 1. Broker on (the default with LLM): the backend probe is the one detector;
#    the shell must not export a window that would outrank it.
out=$(run_dev "$loaded_root" lmstudio qwen/qwen3-27b)
assert_contains "$out" "Broker:    on" "broker on by default"
assert_not_contains "$out" "reported by LM Studio" "broker on: shell exports no window"
assert_contains "$out" "broker probe" "broker on: says the backend probe measures the window"

# 2. --no-broker: no backend probe runs, so the shell detector still reports
#    the LOADED window of the requested model (openai/ routing prefix stripped).
out=$(run_dev "$loaded_root" lmstudio qwen/qwen3-27b --no-broker)
assert_contains "$out" "Context:   262144 tokens (reported by LM Studio)" "no broker: loaded window exported"

# 3. --no-broker, a model with only an advertised maximum: max_context_length is
#    not a loaded window (W3), so nothing is exported.
out=$(run_dev "$max_root" lmstudio qwen/qwen3-27b --no-broker)
assert_not_contains "$out" "reported by LM Studio" "no broker: max_context_length is never used"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
