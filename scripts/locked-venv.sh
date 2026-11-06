#!/usr/bin/env sh
#
# scripts/locked-venv.sh — build a virtualenv from a hashed lockfile and nothing
# else. The lockfiles (agents/requirements-frozen.txt and the dev lockfiles that
# gen-lockfile.sh writes beside it) are what the cooldown (scripts/lock-date.txt)
# and the CI pip-audit gate apply to, so an install from anywhere else skips both:
#   - third-party packages: the lockfile only, wheels only, each checked against
#     its hash (as the release build installs them);
#   - pip: none in the venv. pip runs from the build interpreter (--python), as
#     ensurepip's bundled copy predates the lockfile's audit, and upgrading it
#     from the index would skip the cooldown;
#   - first-party packages: loaded from the checkout through a path file, as the
#     launcher's PYTHONPATH and the release load them. `pip install -e` would
#     build them, fetching their build backend (hatchling) from the index unpinned.
# The venv keeps a copy of the lockfile it was built from. It is recreated when
# the lockfile changes, which drops anything installed outside it, and is left
# as it is otherwise.
#
# Usage: scripts/locked-venv.sh [--force] <venv-dir> <lockfile> [<first-party-dir>...]
#   --force   recreate the venv even when it matches the lockfile
set -eu

die() {
    printf 'locked-venv: %s\n' "$*" >&2
    exit 1
}

force=0
if [ "${1:-}" = "--force" ]; then
    force=1
    shift
fi
[ $# -ge 2 ] || die "usage: locked-venv.sh [--force] <venv-dir> <lockfile> [<first-party-dir>...]"
venv=$1 lock=$2
shift 2
[ -f "$lock" ] || die "no lockfile at $lock"
py=$(command -v python3 || command -v python) || die "Python 3 not found"
stamp="$venv/$(basename "$lock")"

# up_to_date — the venv was built from this exact lockfile and still runs.
up_to_date() {
    [ "$force" -eq 0 ] && cmp -s "$lock" "$stamp" && "$venv/bin/python" -c '' 2>/dev/null
}

# install — recreate the venv empty, with no pip, and install the lockfile into
# it. The copy of the lockfile is written last, so a failed install is retried.
install() {
    "$py" -m pip --version >/dev/null 2>&1 || die "pip not found for $py (install python3-pip)"
    "$py" -m venv --clear --without-pip "$venv" || die "could not create $venv"
    # PYTHONNOUSERSITE + empty PYTHONPATH, as the release build: pip must not
    # count a package outside the venv as already installed.
    PYTHONNOUSERSITE=1 PYTHONPATH='' "$py" -m pip --python "$venv/bin/python" install \
        --quiet --disable-pip-version-check --require-hashes --only-binary :all: -r "$lock" \
        || die "installing $lock failed (above). It needs pip >= 22.3 (for --python) and a wheel of every pin for this Python; the lockfiles target Python 3.12."
    cp "$lock" "$stamp"
}

# link <dir>... — put each first-party directory on the venv's sys.path through
# one path file.
link() {
    site=$("$venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
    : > "$site/vulture-first-party.pth"
    for dir; do
        (CDPATH='' cd -- "$dir" && pwd) >> "$site/vulture-first-party.pth"
    done
}

if up_to_date; then
    echo "locked-venv: $venv already matches $lock"
else
    echo "locked-venv: building $venv from $lock with $("$py" --version 2>&1)"
    install
fi
link "$@"
