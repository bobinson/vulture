#!/usr/bin/env sh
# Tests for scripts/lib/envflag.sh (feature 0074): the launchers read
# VULTURE_USE_LLM with the SAME token list as Go config.ParseFlag and the
# agents' shared.env (on/true/1/yes, case-insensitive, surrounding whitespace
# ignored). The broker gate used to compare against the literal "true", so
# VULTURE_USE_LLM=on ran the LLM while the launcher left the broker off.
#
# The token cases come from the Go fixture both runtimes are already held to,
# so the shell cannot drift from them. VULTURE_USE_LLM defaults to off, so a
# "default" verdict (blank, unrecognised) must read as off.
#
# POSIX sh; the launchers are bash and invoked with bash explicitly.
# Run: scripts/tests/test_env_flag.sh
set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"
ROOT="$(repo_root "$0")"
# shellcheck source=scripts/lib/envflag.sh
. "$ROOT/scripts/lib/envflag.sh"
FIXTURE="$ROOT/backend/internal/config/testdata/flag_tokens_0074.json"

# check <label> <cmd...> — pass when <cmd> succeeds, else fail.
check() {
    label="$1"; shift
    if "$@"; then pass "$label"; else fail "$label" "check failed"; fi
}

# expect <value> <true|false> — env_flag_on and env_flag_word agree on <value>.
expect() {
    if env_flag_on "$1"; then got=true; else got=false; fi
    got="$got/$(env_flag_word "$1")"
    check "'$1' -> $2 (got $got)" [ "$got" = "$2/$2" ]
}

echo "test_env_flag:"
for v in on 1 yes TRUE true On ' YES '; do expect "$v" true; done
for v in false '' '   ' off 0 no flase maybe 2; do expect "$v" false; done

if command -v python3 >/dev/null 2>&1; then
    cases=$(python3 -c 'import json,sys
for c in json.load(open(sys.argv[1]))["cases"]:
    print("%s|%s" % (c["value"], "true" if c["verdict"] is True else "false"))' "$FIXTURE")
    while IFS='|' read -r value want; do expect "$value" "$want"; done <<EOF
$cases
EOF
fi

# Both launchers gate the broker and show the LLM switch through the helper;
# no literal "true" comparison of VULTURE_USE_LLM survives.
for f in start.sh prod_start.sh; do
    path="$ROOT/scripts/$f"
    check "$f sources envflag.sh" grep -q 'lib/envflag.sh' "$path"
    check "$f gates the broker via env_flag_on" grep -qF "env_flag_on \"\${VULTURE_USE_LLM:-}\"" "$path"
    if grep -nE 'VULTURE_USE_LLM:-false\}"? *[!=]=' "$path"; then
        fail "$f: no literal VULTURE_USE_LLM comparison" "found above"
    else
        pass "$f: no literal VULTURE_USE_LLM comparison"
    fi
done

# The launchers still resolve end to end with the helper sourced.
has() { printf '%s' "$1" | grep -qF "$2"; }
lacks() { ! has "$1" "$2"; }
dry() {
    VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE=/dev/null VULTURE_DB_PASSWORD=pw \
        OPENAI_API_KEY=dummy bash "$ROOT/scripts/$1" "$2" 2>&1
}
for f in start.sh prod_start.sh; do
    out=$(dry "$f" openai)
    check "$f openai: LLM true" has "$out" "LLM:       true"
    check "$f openai: broker on" has "$out" "Broker:    on"
    out=$(dry "$f" skills)
    check "$f skills: LLM false" has "$out" "LLM:       false"
    check "$f skills: broker off" lacks "$out" "Broker:    on"
done

finish
