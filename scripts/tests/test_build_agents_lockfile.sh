#!/usr/bin/env sh
#
# Behaviour tests for `scripts/build.sh agents` (through scripts/locked-venv.sh):
# the agents venv is built from the hashed lockfile (agents/requirements-frozen.txt)
# and nothing else. That
# file is the one the cooldown (scripts/lock-date.txt) and the CI pip-audit gate
# apply to, so any other install (a fresh resolve, `pip install -e`, a pip
# self-upgrade) reaches the index past both.
#
# Hermetic: build.sh runs from a copy in a sandbox tree whose python3 and venv
# python are stubs that log every call, so no test touches the real venv or the
# network. The stub pip "installs" by creating a uvicorn marker in the venv.
#
# Harness contract (matches scripts/tests/test_install_sh.sh): POSIX sh, set -u,
# pass()/fail() counters, a final "N passed, M failed" line, exit 1 on any FAIL.

set -u
# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

ROOT=$(repo_root "$0")
require_file_or_bail "build.sh present" "$ROOT/scripts/build.sh"
make_sandbox

STUBS="$SANDBOX/stubbin"
mkdir -p "$STUBS" "$SANDBOX/home"

# The interpreter build.sh finds on PATH: venv creation and pip.
cat > "$STUBS/python3" <<'EOF'
#!/bin/sh
printf 'outer nousersite=%s pythonpath=%s %s\n' "${PYTHONNOUSERSITE:-}" "${PYTHONPATH:-}" "$*" >> "$STUB_LOG"
case "$1 ${2:-} ${3:-}" in
    "--version  ") echo "Python 3.12.0" ;;
    "-m pip --version") echo "pip 26.0" ;;
    "-m pip --python")
        [ -z "${STUB_PIP_FAIL:-}" ] || exit 1
        mkdir -p "$(dirname -- "$4")/../site/uvicorn" ;;
    "-m venv "*)
        for a; do dir=$a; done
        case " $* " in *" --clear "*) rm -rf "$dir" ;; esac
        mkdir -p "$dir/bin" "$dir/site"
        cp "$STUB_VENV_PY" "$dir/bin/python" ;;
esac
EOF

# The venv's interpreter: its site-packages, and whether uvicorn imports.
cat > "$STUBS/venv-python" <<'EOF'
#!/bin/sh
printf 'venv %s\n' "$*" >> "$STUB_LOG"
site="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)/site"
case "$*" in
    *sysconfig*) echo "$site" ;;
    *"import uvicorn"*) [ -d "$site/uvicorn" ] ;;
esac
EOF
chmod +x "$STUBS/python3" "$STUBS/venv-python"

# fresh_repo <name> — a checkout with build.sh, a lockfile and two packages;
# sets REPO, VENV, LOCK and LOG.
fresh_repo() {
    REPO="$SANDBOX/$1"
    VENV="$REPO/agents/.venv"
    LOCK="$REPO/agents/requirements-frozen.txt"
    LOG="$SANDBOX/$1.log"
    mkdir -p "$REPO/scripts" "$REPO/agents/shared" "$REPO/agents/cwe"
    cp "$ROOT/scripts/build.sh" "$ROOT/scripts/locked-venv.sh" "$REPO/scripts/"
    printf 'uvicorn==0.54.0 \\\n    --hash=sha256:%064d\n' 0 > "$LOCK"
    : > "$REPO/agents/shared/pyproject.toml"
    : > "$REPO/agents/cwe/pyproject.toml"
}

# build [VAR=value...] — run `build.sh agents` in $REPO with the stubs first on
# PATH and a caller PYTHONPATH pip must not see; the log restarts each run.
build() {
    : > "$LOG"
    /usr/bin/env HOME="$SANDBOX/home" PATH="$STUBS:/usr/bin:/bin" PYTHONPATH=/caller/path \
        STUB_LOG="$LOG" STUB_VENV_PY="$STUBS/venv-python" "$@" \
        bash "$REPO/scripts/build.sh" agents > "$LOG.out" 2>&1
}

# calls <ere> — how many logged calls match <ere>.
calls() { grep -Ec -- "$1" "$LOG"; }

# expect <name> <detail> <command...> — pass <name> when the command succeeds,
# else fail it with <detail>.
expect() {
    name=$1 detail=$2
    shift 2
    if "$@"; then pass "$name"; else fail "$name" "$detail"; fi
}

PIP_INSTALL='-m pip .*install'
VENV_CREATE='-m venv '
NOT_LOCKED=' -e |--editable|--upgrade| -U '

# --- a fresh build ------------------------------------------------------------
fresh_repo fresh
build; rc=$?
expect "fresh build succeeds" "$(tail -5 "$LOG.out")" [ "$rc" -eq 0 ]

n=$(calls "$PIP_INSTALL")
expect "exactly one pip install" "saw $n" [ "$n" -eq 1 ]

line=$(grep -E -- "$PIP_INSTALL" "$LOG" | head -1)
detail=""
for want in "--require-hashes" "--only-binary :all:" "-r $LOCK" "--python $VENV/bin/python"; do
    case "$line" in *" $want"*) ;; *) detail="$detail missing '$want';" ;; esac
done
verdict "the install is the hashed lockfile, wheels only, into the venv" "$detail"

case "$line" in
    "outer nousersite=1 pythonpath= "*) detail="" ;;
    *) detail=$line ;;
esac
verdict "pip ignores the caller's PYTHONPATH and user site" "$detail"

n=$(calls "$NOT_LOCKED")
expect "no editable install and no upgrade" "$(grep -E -- "$NOT_LOCKED" "$LOG")" [ "$n" -eq 0 ]

n=$(calls "$VENV_CREATE.*--without-pip")
expect "the venv is created without a pip of its own" "$(grep -E -- "$VENV_CREATE" "$LOG")" [ "$n" -eq 1 ]

expect "the venv records the lockfile it was built from" "no copy at $VENV/requirements-frozen.txt" \
    cmp -s "$LOCK" "$VENV/requirements-frozen.txt"

pth=$(cat "$VENV"/site/*.pth 2>/dev/null)
want=$(printf '%s\n%s' "$REPO/agents/cwe" "$REPO/agents/shared")
expect "first-party packages load from the checkout through a path file" "got: $pth" [ "$pth" = "$want" ]

# --- rebuilds -----------------------------------------------------------------
build
n=$(calls "$PIP_INSTALL|$VENV_CREATE")
expect "unchanged lockfile: nothing reinstalled" "$(cat "$LOG")" [ "$n" -eq 0 ]

printf '# re-locked\n' >> "$LOCK"
build
detail=""
[ "$(calls "$VENV_CREATE.*--clear")" -eq 1 ] || detail="venv not recreated with --clear;"
[ "$(calls "$PIP_INSTALL")" -eq 1 ] || detail="$detail lockfile not reinstalled;"
cmp -s "$LOCK" "$VENV/requirements-frozen.txt" || detail="$detail new lockfile not recorded;"
verdict "changed lockfile: venv recreated and reinstalled" "$detail"

rm -rf "$VENV/site/uvicorn"
build
n=$(calls "$PIP_INSTALL")
expect "unchanged lockfile, uvicorn gone: reinstalled" "$(cat "$LOG")" [ "$n" -eq 1 ]

# --- a venv from an older build: no recorded lockfile, extra packages ---------
fresh_repo old
mkdir -p "$VENV/bin" "$VENV/site/stale_pkg"
cp "$STUBS/venv-python" "$VENV/bin/python"
build
detail=""
[ ! -e "$VENV/site/stale_pkg" ] || detail="stale package survived;"
[ "$(calls "$PIP_INSTALL")" -eq 1 ] || detail="$detail lockfile not installed;"
verdict "a venv not built from the lockfile is replaced" "$detail"

# --- a failed install ---------------------------------------------------------
fresh_repo failing
build STUB_PIP_FAIL=1; rc=$?
expect "a failed lockfile install fails the build" "build.sh exited 0" [ "$rc" -ne 0 ]
expect "a failed install records no lockfile, so the next build retries" "lockfile copy written" \
    [ ! -e "$VENV/requirements-frozen.txt" ]

finish
