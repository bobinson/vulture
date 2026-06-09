#!/usr/bin/env sh
#
# RED-phase docs-honesty tests for feature 0055 Tier C.
# Derived ONLY from the 0055 implementation plan (Tier C: C1/C2/C3).
#
# Asserts:
#   C1 README   — Docker-for-agents / "Current limitation" caveat present;
#                 no bald "bundled Python" shipped claim in the Mode-E framing.
#   C2 0044 doc — status reconciled to PARTIAL (not "PLANNED" / "no implementation").
#   C3 guide    — native_installation.md carries a "Current limitations" note
#                 mirroring C1 (Docker for agent scanning).
#
# Same PASS/FAIL/count/exit convention as test_install_sh.sh.

set -u

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS [%s]\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$1" "$2"; }

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
README="$REPO_ROOT/README.md"
GUIDE="$REPO_ROOT/docs/guides/native_installation.md"
STATUS44="$REPO_ROOT/docs/features/0044_native_installer/0044_implementation_status.md"

# ---------------------------------------------------------------------------
# C1a — README has a Docker-for-agents / "Current limitation" caveat.
# ---------------------------------------------------------------------------
name="C1a-readme-docker-for-agents-caveat"
if [ ! -f "$README" ]; then
    fail "$name" "README.md not found at $README"
elif grep -Eqi 'current limitation|agent[s]?.*(require|need)s? *docker|docker *(for|to run).*(agent|llm|scan)|agent-based.*docker' "$README"; then
    pass "$name"
else
    fail "$name" "no 'Current limitation' / 'agents require Docker' caveat found in README"
fi

# ---------------------------------------------------------------------------
# C1b — README must NOT present "bundled Python" as a shipped fact.
# (A future-tense / "planned" mention is fine; a bald shipped claim is not.)
# We flag the pristine Mode-E line: "per-platform tarball + bundled Python".
# ---------------------------------------------------------------------------
name="C1b-readme-no-bald-bundled-python-claim"
if [ ! -f "$README" ]; then
    fail "$name" "README.md not found at $README"
elif grep -Eqi 'tarball *\+ *bundled python|installer.*bundled python|with (a )?bundled python|includes.*bundled python' "$README"; then
    fail "$name" "README still presents 'bundled Python' as a shipped fact (bald claim present)"
else
    pass "$name"
fi

# ---------------------------------------------------------------------------
# C2 — 0044 status reconciled to PARTIAL (not PLANNED / 'no implementation').
# ---------------------------------------------------------------------------
name="C2-0044-status-partial"
if [ ! -f "$STATUS44" ]; then
    fail "$name" "0044_implementation_status.md not found at $STATUS44"
else
    detail=""
    if ! grep -Eqi '\*\*Status\*\*:?[[:space:]]*PARTIAL|^Status:?[[:space:]]*PARTIAL|Status.*PARTIAL' "$STATUS44"; then
        detail="$detail status is not PARTIAL;"
    fi
    if grep -Eqi '\*\*Status\*\*:?[[:space:]]*PLANNED|^Status:?[[:space:]]*PLANNED' "$STATUS44"; then
        detail="$detail status still says PLANNED;"
    fi
    if grep -Eqi 'no implementation work has started|no implementation' "$STATUS44"; then
        detail="$detail still claims no implementation;"
    fi
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
fi

# ---------------------------------------------------------------------------
# C3 — native_installation.md has a "Current limitations" note re: Docker for
#      agent scanning.
# ---------------------------------------------------------------------------
name="C3-guide-current-limitations-note"
if [ ! -f "$GUIDE" ]; then
    fail "$name" "native_installation.md not found at $GUIDE"
elif grep -Eqi 'current limitation' "$GUIDE" && \
     grep -Eqi 'agent[s]?.*(require|need)s? *docker|docker *(for|to run).*(agent|llm|scan)|agent-based.*docker' "$GUIDE"; then
    pass "$name"
else
    fail "$name" "no 'Current limitations' + Docker-for-agents note found in native_installation.md"
fi

# ---------------------------------------------------------------------------
# C3b — the guide must NOT claim a bundled Python is currently SHIPPED
#       (review #6: troubleshooting row + directory-tree entry overclaim).
#       A "planned / not yet / Tier B" mention is fine; a shipped claim is not.
# ---------------------------------------------------------------------------
name="C3b-guide-no-bundled-python-shipped-claim"
if [ ! -f "$GUIDE" ]; then
    fail "$name" "native_installation.md not found at $GUIDE"
elif grep -Eqi 'bundled python is shipped|bundled python.*release tarball|no system python required' "$GUIDE"; then
    fail "$name" "guide still claims a bundled Python is shipped (overclaim; see review #6)"
else
    pass "$name"
fi

# ---------------------------------------------------------------------------
# C5 — build-release.sh must SHIP the committed hashed lockfile (0055 B1),
#      not regenerate a stub. Catches the audit's "claimed-but-not-shipped"
#      gap: the committed lockfile must be hashed AND build-release.sh must
#      copy it into the tarball. (Static check — no Go build needed here.)
# ---------------------------------------------------------------------------
name="C5-build-release-ships-hashed-lockfile"
LOCK="$REPO_ROOT/agents/requirements-frozen.txt"
BR="$REPO_ROOT/scripts/build-release.sh"
detail=""
if [ ! -s "$LOCK" ] || ! grep -q -- '--hash=' "$LOCK"; then
    detail="$detail agents/requirements-frozen.txt missing or unhashed;"
fi
# shellcheck disable=SC2016  # grepping for the literal shell text 'cp "$_lock"' in build-release.sh
if ! grep -q 'cp "$_lock"' "$BR"; then
    detail="$detail build-release.sh no longer copies the hashed lockfile into the tarball;"
fi
if [ -z "$detail" ]; then
    pass "$name"
else
    fail "$name" "$detail"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
