# 0034 — Phase 1 CWE Expansion: Rollback Plan

## Rollback Strategy

All five tasks are committed separately and are independently revertable. Reverting any single task does not require unwinding any earlier one. Rollbacks proceed in reverse task order.

## Reverse-Order Rollback Steps

### Rollback Task 5 — revert threshold change

1. Restore `get_static_detectable(min_score=0.3)` in `agents/cwe/cwe_agent/skills/catalog_detector.py`.
2. Restore the prior scannable-CWE count assertion in `agents/cwe/tests/unit/test_catalog_detector.py` (back to `>= 254`).
3. Re-run `cd agents/cwe && python -m pytest tests/unit/ -q`.

### Rollback Task 4 — remove narrow dedicated skills

For each of the five skill files:

1. Delete `agents/cwe/cwe_agent/skills/<skill>_check.py`.
2. Delete `agents/cwe/tests/unit/test_<skill>_check.py`.
3. Remove the import + `SKILL_MAP` + `SKILL_TOOLS` entries from `agents/cwe/cwe_agent/skills/__init__.py`.
4. Remove the matching entry from `agents/cwe/cwe_agent/config.py::ALL_CATEGORIES`.
5. Remove the new CWE IDs from `_DEDICATED_SKILL_CWES` in `agents/cwe/cwe_agent/skills/catalog_detector.py` (369, 676, 242, 778, 248, 331, 332).
6. Revert `SKILLS.md` and `tests/unit/test_skills.py` category count (22 → 17).

### Rollback Task 3 — remove path-equivalence skill

1. Delete `agents/cwe/cwe_agent/skills/path_equivalence_check.py`.
2. Delete `agents/cwe/tests/unit/test_path_equivalence_check.py`.
3. Remove registration from `skills/__init__.py`.
4. Remove `path_equivalence` from `config.py::ALL_CATEGORIES`.
5. Remove CWE-42/43/46/48–57 from `_DEDICATED_SKILL_CWES` in `catalog_detector.py`.
6. Revert `SKILLS.md` entry and `test_skills.py` category count (17 → 16).

### Rollback Task 2 — remove taxonomic rollup

1. Remove `_parent_children_index` and `get_descendants` from `agents/cwe/cwe_agent/catalog.py`.
2. Remove the rollup-emission block from `catalog_detector._analyze_file`.
3. Delete the rollup tests added to `agents/cwe/tests/unit/test_catalog_detector.py`.

### Rollback Task 1 — revert extractor + catalog JSON

1. Revert `scripts/extract_cwe_catalog.py` to remove `_extract_observed_examples` and the CVE-description/Alternate_Terms keyword mining.
2. Regenerate the catalog JSON:

   ```bash
   cd /home/user/src/vulture && python scripts/extract_cwe_catalog.py \
       docs/cwe_version_4.19.1/cwec_v4.19.1.xml \
       agents/cwe/cwe_agent/data/cwe_catalog.json
   ```

3. Alternatively, restore `cwe_catalog.json` from git: `git checkout <pre-0034-sha> -- agents/cwe/cwe_agent/data/cwe_catalog.json`.
4. Revert `tests/unit/test_catalog.py` assertions that reference `observed_examples`.

## Fast-Path Rollback (all tasks)

If an operational issue in production requires reverting the whole feature:

```bash
git revert <sha_task5>..<sha_task1>   # revert commits in reverse order, inclusive
cd /home/user/src/vulture && make test
```

## Risk Assessment

- **No schema changes** — no database migrations to reverse.
- **No API changes** — `/info` contract unchanged (the `config_schema` adds optional new skill entries; removing them is backwards-compatible because frontends auto-discover).
- **No data-migration risk** — `cwe_catalog.json` is a build-time artifact; regenerating restores prior state.
- **Low blast radius** — additive skill modules; disabling any skill is a one-line config change via env var if an emergency disable is preferred over full revert.

## Emergency Disable (no revert needed)

If a specific new skill produces noise in production, disable at runtime without rollback:

```bash
# Disable a single skill via the agent's category-filter env var
VULTURE_CWE_DISABLE_SKILLS=path_equivalence,weak_entropy docker compose up -d agent-cwe
```

(This relies on the existing per-category disable mechanism in `config.py`; no code change required.)

## Verification After Rollback

Regardless of rollback depth, run:

```bash
cd /home/user/src/vulture && make test
cd agents/cwe && python -m pytest tests/unit/ -q
```

Expected: 186 CWE tests pass, total test count returns to the pre-0034 baseline.
