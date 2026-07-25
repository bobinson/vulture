# 0038 — Rollback Plan

> Per-phase rollback. Both phases are pure code reverts; no data migrations; no compose changes; no schema changes.

## Rollback summary

| Phase | Rollback time | Data loss | User impact |
|---|---|---|---|
| Phase 1 | ~5 minutes | none | XXE protection lost; existing audits unaffected |
| Phase 2 | ~5 minutes | none | git hardening lost; existing audits unaffected |

Worst case full rollback: ~10 minutes. No deployment-state coupling.

---

## Phase 1 — XXE remediation

### Triggers
- defusedxml dependency causes import error in production environment.
- Legitimate XML payload type starts being rejected (would surface as discover scans missing previously-discovered URLs).
- Performance regression > 50% on XML-heavy targets.

### Procedure

1. Revert the merge commit chain for Phase 1 tasks (1.1 → 1.6).
2. Confirm the following files revert to pre-feature state:
   - `agents/shared/pyproject.toml` — `defusedxml>=0.7.1` removed from `dependencies`
   - `agents/shared/shared/safe_input/` directory — **deleted entirely** (xml.py, __init__.py, README.md)
   - `agents/discover/discover_agent/plugins/_shared.py` — local `safe_xml_parse` definition restored; import from `shared.safe_input.xml` removed
   - `agents/discover/discover_agent/plugins/crawl.py` — restored `# noqa: S314` line and `from xml.etree import ElementTree` import; reverted to `ElementTree.fromstring`
   - Test files `agents/shared/tests/unit/safe_input/test_xml.py` and `agents/discover/tests/unit/test_crawl_sitemap_xxe.py` — deleted
   - `agents/shared/tests/unit/safe_input/__init__.py` — deleted (with empty dir cleanup)
   - `Makefile` — `lint-no-direct-unsafe-input` target removed (or sections 1+2 stripped if Phase 2 is also being rolled back)
3. Rebuild discover + shared images.
4. Restart agents.

**Special note**: rolling back Phase 1 also nullifies the `safe_input/` package foundation. If Phase 2 has shipped, **roll Phase 2 back first** (since Phase 2's `safe_input/git.py` lives in the same package). Rolling back Phase 1 alone while Phase 2 is in production breaks Phase 2's imports.

### Per-test rollback
Individual XXE rules cannot be rolled back per-rule; defusedxml is a single integration point. Either the protection is on or off.

### Forward fix preferred over rollback
If a legitimate XML payload type is being rejected:
1. **Inspect the rejected sample** — does it contain a DOCTYPE that legitimately doesn't need entity expansion?
2. **Adjust the `forbid_dtd=True` flag**: the `forbid_dtd=True` argument can be loosened to `forbid_dtd=False` for that specific call site if the use case is well-understood, while keeping `forbid_entities=True` and `forbid_external=True` (the actually-dangerous parts).
3. Document the exception in the call site's docstring.

This is preferable to full rollback because XXE protection on the OTHER call sites stays intact.

### Verification post-rollback

```bash
# 1. defusedxml dep removed
grep -c defusedxml agents/discover/pyproject.toml
# Expected: 0

# 2. Lint rule removed
make lint-no-unsafe-xml 2>&1 | head -3
# Expected: "make: *** No rule to make target 'lint-no-unsafe-xml'"

# 3. Test file removed
ls agents/discover/tests/unit/test_xml_xxe_protection.py 2>&1
# Expected: "No such file or directory"

# 4. Function signature unchanged (smoke test)
python3 -c "from discover_agent.plugins._shared import safe_xml_parse; \
    print(safe_xml_parse('<a/>') is not None)"
# Expected: True
```

---

## Phase 2 — Git clone + command hardening

### Triggers
- Hardening flag rejects a previously-working clone (most likely culprit: `core.symlinks=false` breaking a project relying on symlinks).
- `safe.directory=*` policy conflicts with a future security policy (unlikely).
- Per-flag side effect surfaces in production (e.g., a project's CI relies on git invoking a custom editor — unlikely for `git log` but possible for other operations).

### Procedure

1. Revert the merge commit chain for Phase 2 tasks (2.1 → 2.7).
2. Confirm the following files revert to pre-feature state:
   - `backend/pkg/gitutil/hardening.go` — **deleted**
   - `backend/pkg/gitutil/clone.go` — `Clone` no longer prepends hardening flags
   - `backend/pkg/gitutil/info.go` — `isGitRepo` and `gitCmd` no longer prepend hardening flags
   - `agents/shared/shared/safe_input/git.py` — **deleted**
   - `agents/shared/shared/safe_input/__init__.py` — `git` re-exports removed; `safe_xml_parse` re-export retained if Phase 1 is still shipped
   - `agents/shared/shared/tools/git_history.py` — restored to manual `cmd = ["git", ...]` construction; `from shared.safe_input.git import build_git_command` removed
   - Test files `hardening_test.go`, `clone_security_test.go`, `agents/shared/tests/unit/safe_input/test_git.py` — deleted
   - `Makefile` — sections 5+6 (Python git, Go git) stripped from `lint-no-direct-unsafe-input`. The rule itself stays (still covers Phase 1 XML).
3. Rebuild backend image. Rebuild agent images.

**Special note**: Phase 2's `safe_input/git.py` lives in the same package as Phase 1's `safe_input/xml.py`. Rolling back Phase 2 alone leaves the package + Phase 1 contents intact (preferred); rolling back Phase 1 also requires removing or accommodating Phase 2's git module.

### Per-flag rollback (preferred to full rollback)

If only one hardening flag causes problems, edit `gitHardeningArgs()` (or `gitCloneArgs()`) in `hardening.go` to remove the offending entry:

```go
func gitHardeningArgs() []string {
    return []string{
        "-c", "core.fsmonitor=",
        // Removed: "-c", "core.hooksPath=/dev/null",   // <-- this caused issue X, see ticket Y
        "-c", "core.editor=true",
        "-c", "core.pager=cat",
        "-c", "core.sshCommand=ssh",
        "-c", "safe.directory=*",
    }
}
```

Update `TestGitHardeningArgs_ContainsAllFlags` in `hardening_test.go` to reflect the removal — including a comment explaining why.

This per-flag rollback preserves protection from all other vectors.

### Forward fix for symlink issue (likely scenario)

If `core.symlinks=false` breaks a use case:

1. Confirm the issue: `git clone` succeeds but downstream code fails because what was a symlink is now a regular file containing the symlink target as text.
2. Two options:
   - **Option A**: Move `core.symlinks=false` from `gitCloneArgs()` to a per-call opt-in. Document which Vulture code paths require it.
   - **Option B**: Remove the flag entirely; rely on the fact that `core.protectHFS=true` + `core.protectNTFS=true` already mitigate the CVE-2024-32002 specific case.
3. Update tests; document decision in `hardening.go` comment.

### Verification post-rollback

```bash
# 1. hardening.go absent
ls backend/pkg/gitutil/hardening.go 2>&1
# Expected: "No such file or directory"

# 2. Clone command line shape (smoke test)
cat backend/pkg/gitutil/clone.go | grep -A2 'args := \[\]string{"clone"}'
# Expected: matches pre-feature pattern

# 3. Lint rule removed
make lint-git-hardening 2>&1 | head -3
# Expected: "make: *** No rule to make target"

# 4. Existing tests still pass
cd backend && go test ./pkg/gitutil/ -count=1
# Expected: all pre-existing tests green (clone_test.go, info_test.go)
```

---

## Database / compose / image rollback

**None applicable.** This feature has:
- No database migrations.
- No compose file changes.
- No new container services.
- No new env vars.
- No external dependencies beyond `defusedxml` (Phase 1 only).

---

## User communication

If a phase is rolled back in production:

1. Update `0038_implementation_status.md` with rollback timestamp + reason.
2. Add CHANGELOG entry under the affected version.
3. Audit downstream effects:
   - Phase 1 rollback → re-evaluate XXE risk in production targets, log warning in release notes.
   - Phase 2 rollback → re-evaluate git config injection risk on cloned repos.

---

## Verification post-rollback (full)

```bash
# Phase 1 fully reverted
grep -rn 'defusedxml' agents/ backend/ cli/ mcp/ --include='*.py' --include='*.toml' \
    | grep -v '/tests/' | grep -v '/.venv/'
# Expected: empty

# safe_input package fully removed (only after BOTH phases rolled back)
ls agents/shared/shared/safe_input/ 2>&1
# Expected: "No such file or directory"

# Phase 2 fully reverted
grep -rn 'gitHardeningArgs\|gitCloneArgs\|build_git_command\|GIT_HARDENING_ARGS' \
    backend/ agents/ cli/ --include='*.go' --include='*.py' \
    | grep -v '/.venv/'
# Expected: empty

# Both reverts: existing test suites green
cd backend && go test ./pkg/gitutil/ -count=1
python3 -m pytest agents/discover/tests/unit/ agents/shared/tests/unit/ -q
# Expected: all green
```

If all three commands report cleanly, rollback is complete.

---

## Forward path after rollback

A rollback is not a permanent reversal — it's a release-engineering choice. After a rollback:

1. File a new issue documenting the failure mode.
2. Add a regression test that captures the failure (so a future re-attempt detects it).
3. Re-attempt the feature with the lesson incorporated.

The corpus in `0038_implementation_plan.md` §1.4 and §2.5 must NOT be reduced as part of rollback. Tests stay; they may be `pytest.mark.skip`'d temporarily but never deleted.
