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
# Assert build-release.sh copies a requirements-frozen.txt (behavioural anchor,
# not the exact variable name — survives a benign refactor of the cp line).
if ! grep -qE 'cp[[:space:]].*requirements-frozen\.txt' "$BR"; then
    detail="$detail build-release.sh no longer copies the hashed lockfile into the tarball;"
fi
if [ -z "$detail" ]; then
    pass "$name"
else
    fail "$name" "$detail"
fi

# ---------------------------------------------------------------------------
# C6 — build-release.sh must STAGE plugin manifests into runtime/plugins/ so a
#      native install can discover them (0055 plugin-activation ckpt 3). Ships
#      manifests + rule sidecars only — NOT container images.
# ---------------------------------------------------------------------------
name="C6-build-release-ships-plugin-manifests"
BR="$REPO_ROOT/scripts/build-release.sh"
if grep -qE 'runtime/plugins' "$BR" && grep -qE 'plugin\.toml' "$BR"; then
    pass "$name"
else
    fail "$name" "build-release.sh no longer stages plugin manifests into runtime/plugins/"
fi

# ---------------------------------------------------------------------------
# C7 — Tier B (bundle python-build-standalone). build-release.sh must have an
#      OPT-IN VULTURE_BUNDLE_PBS code path that, WHEN SET, fetches + extracts a
#      REAL CPython 3.12 interpreter into runtime/python/ and does NOT leave the
#      PBS_NOT_BUNDLED marker. When UNSET it keeps today's lean behaviour (write
#      PBS_NOT_BUNDLED). This is a static, build-free assertion on the script.
#
#      Anchors (behavioural, survive benign refactors):
#        - references the VULTURE_BUNDLE_PBS opt-in env var;
#        - the bundle path is GUARDED by that var (so the default release stays
#          lean — PBS_NOT_BUNDLED is only written when the var is NOT set);
#        - downloads a cpython ... 3.12 ... install_only PBS tarball;
#        - SHA256-verifies the download (fail-closed) — must not just curl|tar;
#        - results in a runnable bin/python3.12 under runtime/python/.
# ---------------------------------------------------------------------------
name="C7-build-release-has-pbs-bundle-optin"
BR="$REPO_ROOT/scripts/build-release.sh"
detail=""
if [ ! -f "$BR" ]; then
    fail "$name" "build-release.sh not found at $BR"
else
    grep -q 'VULTURE_BUNDLE_PBS' "$BR" \
        || detail="$detail no VULTURE_BUNDLE_PBS opt-in;"
    # The PBS_NOT_BUNDLED marker must be CONDITIONAL on the opt-in being unset
    # (i.e. an else/guard), not unconditionally written like today.
    if grep -q 'PBS_NOT_BUNDLED' "$BR"; then
        grep -Eq 'VULTURE_BUNDLE_PBS.*(=|!=).*(1|true)|if[[:space:]].*VULTURE_BUNDLE_PBS|else|\bfi\b' "$BR" \
            || detail="$detail PBS_NOT_BUNDLED is not guarded by VULTURE_BUNDLE_PBS;"
        # Heuristic: the marker write must sit inside a conditional block that
        # mentions the opt-in var, so a bundled build does NOT emit it.
        grep -Pzoq '(?s)VULTURE_BUNDLE_PBS.*PBS_NOT_BUNDLED' "$BR" 2>/dev/null \
            || detail="$detail PBS_NOT_BUNDLED not co-located with VULTURE_BUNDLE_PBS guard;"
    fi
    # Real fetch of a 3.12 install_only PBS dist (not a placeholder marker).
    # Behavioural anchor: an install_only cpython asset AND a pinned 3.12.x
    # version both appear — they need not share a line (the asset name is now
    # assembled from PBS_PYVER), so this survives the build-release refactor.
    { grep -Eiq 'cpython-.*install_only|install_only.*\.tar' "$BR" \
        && grep -Eiq 'PBS_PYVER.*3\.12|3\.12\.[0-9]+' "$BR"; } \
        || detail="$detail no cpython 3.12 install_only PBS download;"
    # SHA verification of the fetched tarball (fail-closed), per design item 2.
    grep -Eiq 'SHA256SUMS|sha256sum|sha256_of|--require-hashes' "$BR" \
        || detail="$detail no SHA256 verification of the PBS download;"
    # Extract/flatten so a runnable bin/python3.12 lands under runtime/python/.
    grep -Eq 'runtime/python/bin/python3\.12|bin/python3\.12' "$BR" \
        || detail="$detail no runtime/python/bin/python3.12 produced;"
    if [ -z "$detail" ]; then
        pass "$name"
    else
        fail "$name" "$detail"
    fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
