#!/usr/bin/env sh
# Tests the host-vs-internal Postgres port wiring for the generated DSN
# (config.ini.example + gen-env.sh), and that load_env does not clobber an
# explicitly exported VULTURE_DB_DSN (start.sh).
#
# Regression guard. config.ini.example shipped `[database] port` = the
# CONTAINER-INTERNAL port, while gen-env.sh interpolates that value into a
# HOST-side DSN. `vulture.sh dev --pg` therefore ran the native backend against
#   postgres://vulture:...@localhost:25432/vulture
# and died with "connect: connection refused", because compose only publishes
# the host port (25433). Two mechanisms hid it: the port is specified twice
# ([ports] postgres_host and [database] port) with no cross-check, and --pg's
# corrected export was overwritten when start.sh re-sourced .env.
#
# POSIX sh, since CI runs `shellcheck scripts/tests/*.sh`; start.sh is a bash
# script and is invoked with bash explicitly.
#
# Run: sh scripts/tests/test_db_dsn_wiring.sh
set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

ROOT=$(repo_root "$0")
GEN="$ROOT/scripts/gen-env.sh"
START="$ROOT/scripts/start.sh"
EXAMPLE="$ROOT/config.ini.example"

require_file_or_bail "gen-env.sh present" "$GEN"
require_file_or_bail "start.sh present" "$START"
require_file_or_bail "config.ini.example present" "$EXAMPLE"

make_sandbox

# ini_val <file> <section> <key> — mirrors gen-env.sh's ini_get reader.
ini_val() {
    awk -v sec="[$2]" -v k="$3" '
        /^\[/ { in_sec = ($0 == sec) }
        in_sec && match($0, "^[[:space:]]*"k"[[:space:]]*=") {
            sub(/^[^=]*=[[:space:]]*/, ""); print; exit
        }
    ' "$1"
}

# dsn_of <env-file> — the generated VULTURE_DB_DSN value.
dsn_of() { sed -n 's/^VULTURE_DB_DSN=//p' "$1" | tail -n1; }

# pg_ini <out> [port-line] — the shipped example switched to mode=postgres,
# optionally overriding the [database] port line.
pg_ini() {
    _out="$1"
    sed 's/^mode = sqlite/mode = postgres/' "$EXAMPLE" > "$_out"
    if [ "$#" -ge 2 ]; then
        sed "s/^port     = .*/port     = $2/" "$_out" > "$_out.tmp" && mv "$_out.tmp" "$_out"
    fi
}

HOST_PORT=$(ini_val "$EXAMPLE" ports postgres_host)
INTERNAL_PORT=$(ini_val "$EXAMPLE" ports postgres_internal)

echo "test_db_dsn_wiring:"
echo "  (ports.postgres_host=$HOST_PORT ports.postgres_internal=$INTERNAL_PORT)"

# 1. The shipped example must not aim the DSN at the container-internal port.
#    Empty is fine — that means "derive from ports.postgres_host".
DB_PORT=$(ini_val "$EXAMPLE" database port)
if [ -z "$DB_PORT" ] || [ "$DB_PORT" = "$HOST_PORT" ]; then
    pass "example [database] port targets the published host port"
else
    fail "example [database] port targets the published host port" \
        "port=$DB_PORT but ports.postgres_host=$HOST_PORT; the internal port is unreachable from the host"
fi

# 2. gen-env on the shipped example (mode=postgres) yields a host-reachable DSN.
pg_ini "$SANDBOX/a.ini"
if bash "$GEN" "$SANDBOX/a.ini" "$SANDBOX/a.env" >"$SANDBOX/a.log" 2>&1; then
    got=$(dsn_of "$SANDBOX/a.env")
    case "$got" in
        *"@localhost:$HOST_PORT/"*)
            pass "generated DSN uses the host port" ;;
        *)
            fail "generated DSN uses the host port" "got '$got', want ':$HOST_PORT'" ;;
    esac
else
    fail "generated DSN uses the host port" "gen-env exited non-zero: $(cat "$SANDBOX/a.log")"
fi

# 3. An empty [database] port derives the host port instead of emitting a
#    portless DSN — removes the duplicate source of truth for the common
#    compose case.
pg_ini "$SANDBOX/b.ini" ""
if bash "$GEN" "$SANDBOX/b.ini" "$SANDBOX/b.env" >"$SANDBOX/b.log" 2>&1; then
    got=$(dsn_of "$SANDBOX/b.env")
    case "$got" in
        *"@localhost:$HOST_PORT/"*)
            pass "empty [database] port derives ports.postgres_host" ;;
        *)
            fail "empty [database] port derives ports.postgres_host" "got '$got', want ':$HOST_PORT'" ;;
    esac
else
    fail "empty [database] port derives ports.postgres_host" \
        "gen-env exited non-zero: $(cat "$SANDBOX/b.log")"
fi

# 4. Explicitly pointing a localhost DSN at the container-internal port is the
#    original bug: gen-env must refuse rather than emit an unreachable DSN.
pg_ini "$SANDBOX/c.ini" "$INTERNAL_PORT"
if bash "$GEN" "$SANDBOX/c.ini" "$SANDBOX/c.env" >"$SANDBOX/c.log" 2>&1; then
    fail "internal port on localhost is refused" \
        "gen-env succeeded and emitted '$(dsn_of "$SANDBOX/c.env")'"
else
    if grep -q "$INTERNAL_PORT" "$SANDBOX/c.log" && grep -qi "port" "$SANDBOX/c.log"; then
        pass "internal port on localhost is refused"
    else
        fail "internal port on localhost is refused" \
            "failed, but the message never names the port: $(cat "$SANDBOX/c.log")"
    fi
fi

# 5. A host-installed Postgres on its own port is legitimate and must pass —
#    the guard in case 4 must not fire on every non-compose port.
pg_ini "$SANDBOX/d.ini" 5432
if bash "$GEN" "$SANDBOX/d.ini" "$SANDBOX/d.env" >"$SANDBOX/d.log" 2>&1; then
    got=$(dsn_of "$SANDBOX/d.env")
    case "$got" in
        *"@localhost:5432/"*)
            pass "host-install port is preserved" ;;
        *)
            fail "host-install port is preserved" "got '$got', want ':5432'" ;;
    esac
else
    fail "host-install port is preserved" "gen-env exited non-zero: $(cat "$SANDBOX/d.log")"
fi

# 6. load_env must not clobber an exported VULTURE_DB_DSN. This is what makes
#    `vulture.sh dev --pg` authoritative: it exports the corrected DSN, then
#    execs start.sh, whose load_env re-sources .env with `set -a`.
printf 'VULTURE_DB_DSN=postgres://vulture:envfile@localhost:%s/vulture?sslmode=disable\n' \
    "$INTERNAL_PORT" > "$SANDBOX/dotenv"
VULTURE_DB_DSN="postgres://vulture:exported@localhost:$HOST_PORT/vulture?sslmode=disable"
export VULTURE_DB_DSN
out=$(VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE="$SANDBOX/dotenv" bash "$START" skills 2>&1)
unset VULTURE_DB_DSN
case "$out" in
    *":$HOST_PORT/vulture"*)
        pass "exported VULTURE_DB_DSN survives load_env" ;;
    *)
        fail "exported VULTURE_DB_DSN survives load_env" \
            "the .env value won (or no DB line was printed); output: $out" ;;
esac

# 7. With nothing exported, the .env value is still used — the preserve-export
#    fix must not stop .env from supplying the DSN.
out=$(VULTURE_LAUNCH_DRY_RUN=1 VULTURE_ENV_FILE="$SANDBOX/dotenv" bash "$START" skills 2>&1)
case "$out" in
    *":$INTERNAL_PORT/vulture"*)
        pass "unset VULTURE_DB_DSN falls back to .env" ;;
    *)
        fail "unset VULTURE_DB_DSN falls back to .env" \
            "expected the .env DSN on port $INTERNAL_PORT; output: $out" ;;
esac

# 8. The printed DB line must not leak the password.
case "$out" in
    *envfile*)
        fail "DB summary line masks the password" "the password appears verbatim: $out" ;;
    *)
        pass "DB summary line masks the password" ;;
esac

finish
