#!/usr/bin/env sh
#
# scripts/release-preflight.sh — feature 0055 pre-tag release gate.
#
# Runs the gates that MUST pass before a release tag is cut, failing LOUDLY
# (non-zero) the moment any gate fails. Invoked by `scripts/vulture.sh release`.
#
# Usage:
#   scripts/release-preflight.sh [<tag>]   run every gate (tag passed to the
#                                          fallback-tag check; optional)
#   scripts/release-preflight.sh --help    LIST the gates and exit 0 WITHOUT
#                                          running any of them (dry/listing path)
#
# Gates, in order (the cheap, instant clean-tree gate runs FIRST so a dirty tree
# fails fast before the slower lockfile/shellcheck/test gates spend any work):
#   1. clean git tree         git status / git diff (no uncommitted changes)
#   2. lockfile freshness     scripts/check-lockfile.sh
#   3. fallback-tag validity  scripts/check-fallback-tag.sh <tag>
#   4. shellcheck             install.sh + scripts/*.sh + scripts/lib/*.sh
#   5. installer branch tests scripts/tests/test_install_sh.sh
#
# POSIX sh, no bashisms. Tiny functions (cyclomatic < 5), DRY.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)

# print_gates — enumerate the gates (used by --help AND as the run banner). The
# keywords here are the contract the listing path advertises; keep them stable.
print_gates() {
    cat <<'EOF'
release preflight — pre-tag gates (all must pass before tagging; clean-tree first, fail-fast):
  1. clean git tree          no uncommitted changes (git status)
  2. lockfile freshness      scripts/check-lockfile.sh
  3. fallback-tag validity   scripts/check-fallback-tag.sh <tag>
  4. shellcheck              install.sh + scripts/*.sh + scripts/lib/*.sh
  5. installer branch tests  scripts/tests/test_install_sh.sh
EOF
}

# die <msg> — report a tripped gate on stderr and exit LOUDLY (non-zero).
die() {
    echo "release preflight: FAILED — $1" >&2
    exit 1
}

# run_gate <label> <cmd...> — announce a gate, run it, die LOUDLY on failure.
run_gate() {
    _label=$1
    shift
    echo "==> gate: $_label"
    "$@" || die "$_label"
}

# gate_shellcheck — shellcheck install.sh + every scripts/*.sh AND scripts/lib/*.sh
# (the scripts/*.sh glob does NOT recurse, so the sourced lib helpers must be
# listed explicitly). Skip if the tool is absent so the gate is portable; CI
# installs it.
gate_shellcheck() {
    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "    shellcheck not installed — skipping (install in CI)"
        return 0
    fi
    shellcheck "$REPO_ROOT/install.sh" "$REPO_ROOT"/scripts/*.sh "$REPO_ROOT"/scripts/lib/*.sh
}

# gate_clean_tree — fail if the working tree has uncommitted (tracked) changes
# or staged changes. Runs from REPO_ROOT so `git status` / `git diff` see the
# real tree (no -C, so the gate scripts read literally for the contract).
gate_clean_tree() (
    cd "$REPO_ROOT" || die "cannot enter repo root"
    [ -z "$(git status --porcelain)" ] \
        || die "working tree is dirty (uncommitted changes); commit or stash first"
    git diff --quiet || die "unstaged changes present"
)

# --help / -h: list the gates and exit WITHOUT running anything.
case "${1:-}" in
    -h|--help)
        print_gates
        exit 0
        ;;
esac

TAG=${1:-}

echo "==> vulture release preflight"
print_gates
echo

# Clean-tree FIRST: it is the cheap, instant gate, so a dirty working tree fails
# fast before the slower lockfile/shellcheck/branch-test gates spend any work.
# Gate scripts carry their own shebang (check-lockfile.sh / check-fallback-tag.sh
# are bash; test_install_sh.sh is sh) — invoke them directly so each runs under
# its declared interpreter rather than being forced under this script's sh.
run_gate "clean git tree"         gate_clean_tree
run_gate "lockfile freshness"     "$SCRIPT_DIR/check-lockfile.sh"
run_gate "fallback-tag validity"  "$SCRIPT_DIR/check-fallback-tag.sh" "$TAG"
run_gate "shellcheck"             gate_shellcheck
run_gate "installer branch tests" "$SCRIPT_DIR/tests/test_install_sh.sh"

echo "==> release preflight: ALL GATES PASSED"
