#!/usr/bin/env sh
# The LM Studio context-window probe must never abort the launcher.
#
# start.sh runs under `set -euo pipefail`. `detect_lmstudio_ctx` asks the
# server's native `/api/v0/models` for the loaded window; a server that does
# not expose it (a 404, an OpenAI-compatible stand-in) made the probe's
# pipeline fail, and the failed command substitution ended the launcher
# silently right after "Auto-detected model". The probe's contract is that a
# failure is silent and the normal window resolution applies.
#
# Run: scripts/tests/test_lmstudio_ctx_probe.sh
set -u
# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

ROOT="$(repo_root "$0")"
make_sandbox

# A stub server: /v1/models answers, /api/v0/models is a 404.
mkdir -p "$SANDBOX/www/v1"
printf '{"data":[{"id":"stub-model"}]}' > "$SANDBOX/www/v1/models"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
( cd "$SANDBOX/www" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
STUB=$!
trap 'kill "$STUB" 2>/dev/null; rm -rf "$SANDBOX"' EXIT INT TERM
i=0
while ! curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null 2>&1 && [ "$i" -lt 50 ]; do
    sleep 0.1; i=$((i + 1))
done

probe() {
    # $1 = base url. Prints "rc=<status> ctx=<value>" from a strict-mode shell.
    bash -c '
        set -euo pipefail
        eval "$(sed -n "/^detect_lmstudio_ctx()/,/^}/p" "$1")"
        _LM_CTX="$(detect_lmstudio_ctx "$2" "openai/stub-model")"
        echo "survived ctx=${_LM_CTX}"
    ' _ "$ROOT/scripts/start.sh" "$1" 2>&1
}

out=$(probe "http://127.0.0.1:$PORT/v1")
case "$out" in
    *"survived ctx="*) pass "a 404 from /api/v0/models does not abort strict mode" ;;
    *) fail "a 404 from /api/v0/models does not abort strict mode" "got: $out" ;;
esac
if [ "$out" = "survived ctx=" ]; then
    pass "no window is reported when the probe fails"
else
    fail "no window is reported when the probe fails" "got: $out"
fi

out=$(probe "http://127.0.0.1:1/v1")
case "$out" in
    *"survived ctx="*) pass "an unreachable server does not abort strict mode" ;;
    *) fail "an unreachable server does not abort strict mode" "got: $out" ;;
esac

finish
