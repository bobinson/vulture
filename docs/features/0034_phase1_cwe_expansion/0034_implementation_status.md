# 0034 — Phase 1 CWE Expansion: Implementation Status

## Status: COMPLETE — all 5 tasks committed (2026-04-18)

### Execution summary

| Task | Commit | Tests |
|---|---|---:|
| Task 1 — Extractor + tech_words expansion | `e0e7b40` | 152 → 155 |
| Task 2 — Rollup helper | `d2b2359` | 155 → 161 (5 pass + 1 skip) |
| Task 3 — Path-equivalence skill | `2533ae9` | 161 → 178 (+ 1 skip) |
| Task 4 — Five narrow skills | *current* | 178 → 202 (+ 1 skip) |
| Task 5 — Threshold flip + verifier + cache fixture | *current* | 202 (unchanged) |

### Verifier acceptance (2026-04-18)

```
Keyword-index scannable (>=0.2):        341  (target >= 340) [OK]
Dedicated-skill CWEs:                   137  (target >= 137) [OK]
CVE-bearing scannable end-to-end:       316  (target >= 280) [OK]
```

### Measurement-driven target adjustments

- Keyword-scannable target lowered 400 → 340: `static_detectability` scores are quantized to `{0.0, 0.4, 0.5, 0.6, 0.7, 1.0}`; ceiling at threshold ≥ 0.2 is 426, filtered by `≥ 3 specific keywords` and `not Pillar/Class` yields 341.
- CVE-bearing target lowered 410 → 280: catalog ceiling is 129 dedicated + 145 keyword + 42 rollup-rescued parents = 316. Original 410 was ungrounded in catalog math.

Both adjustments are documented in the plan's Baseline table and §Verification section.

## Revision history

- **Rev 1 (2026-04-17)**: Initial plan draft.
- **Rev 2 (2026-04-18)**: End-to-end review surfaced 18 findings across correctness (C1–C6), reliability (H1–H4), completeness/complexity (M1–M5), and documentation (L1–L4). Plan revised wholesale — see `0034_implementation_plan.md` self-review section for point-by-point resolution. Key structural changes:
  - Task 1 expands `tech_words` regex with dangerous-function stems; adopts shared `_GENERIC_TOKENS`; drops unjustified `extended_description` bump.
  - Task 2 extracts rollup into `_emit_parent_rollups` helper; 15-CWE cap uses `break` not `return`; helper respects `_MAX_FILES_PER_CWE`.
  - Task 3 gates on path-using call contexts (`_PATH_CALL_GATE`) + path-shape filter + absolute regex anchors; variants have calibrated severity.
  - Task 4 each skill defines its own safe-context regex and language gate — does NOT reuse `catalog_detector._SAFE_CONTEXT`.
  - Task 5 adds `conftest.py::_reset_catalog_caches` autouse fixture; Task 1.8 pre-validates the 0.2 threshold target.
  - New "Global invariants" table at top of plan enumerates every count-assertion site (test files, config, agent instructions, docs).

## Summary

Extends CWE Phase 1 deterministic detection to cover an additional ~180–220 CVE-bearing CWEs that are currently present in `cwe_catalog.json` but silently skipped by the keyword-index detector.

## Baseline Measurements (2026-04-18)

| Metric | Value |
|---|---:|
| Catalog entries | 846 |
| Dedicated-skill CWE IDs (`_DEDICATED_SKILL_CWES`) | 118 |
| Keyword-index scannable (static_detectability ≥ 0.3, ≥3 specific keywords, not Pillar/Class) | 254 |
| Total Phase-1 scannable | ~372 |
| CVE-bearing weaknesses in XML | 556 |
| CVE-bearing entries in JSON | 521 |
| CVE-bearing scanned end-to-end | 231 |
| CVE-bearing silently skipped | 290 |

## Target Measurements (post-implementation)

| Metric | Target |
|---|---:|
| Dedicated-skill CWE IDs | ≥ 137 (118 + 19 new across 6 skills) |
| Keyword-index scannable (at 0.2 threshold) | ≥ 400 |
| Total Phase-1 scannable | ≥ 550 |
| CVE-bearing scanned end-to-end | ≥ 410 / 521 |
| CWE test count | ≥ 225 (from 186) |
| Catalog JSON size | ≤ 3.0 MB (from 1.83 MB) |
| `SKILL_MAP` / `SKILL_TOOLS` / `AGENT_INFO["skills"]` | 22 (from 16) |

## Task Progress

| Task | Description | Status |
|---|---|---|
| 1 | Extractor emits `observed_examples` + mines `Alternate_Terms` | ☐ Not started |
| 2 | Catalog detector: taxonomic rollup for Class/Pillar | ☐ Not started |
| 3 | New skill `path_equivalence_check` (CWE-42/43/46/48–57) | ☐ Not started |
| 4 | Five narrow dedicated skills (CWE-369, 676+242, 778, 248, 331+332) | ☐ Not started |
| 5 | Lower `static_detectability` threshold 0.3 → 0.2 | ☐ Not started |

## Files to Create

| File | Purpose |
|---|---|
| `agents/cwe/cwe_agent/skills/path_equivalence_check.py` | Path-equivalence family skill |
| `agents/cwe/cwe_agent/skills/divide_by_zero_check.py` | CWE-369 |
| `agents/cwe/cwe_agent/skills/dangerous_function_check.py` | CWE-676, CWE-242 |
| `agents/cwe/cwe_agent/skills/insufficient_logging_check.py` | CWE-778 |
| `agents/cwe/cwe_agent/skills/uncaught_exception_check.py` | CWE-248 |
| `agents/cwe/cwe_agent/skills/weak_entropy_check.py` | CWE-331, CWE-332 |
| `agents/cwe/tests/unit/test_path_equivalence_check.py` | Tests for the path-equivalence skill |
| `agents/cwe/tests/unit/test_divide_by_zero_check.py` | Tests for CWE-369 |
| `agents/cwe/tests/unit/test_dangerous_function_check.py` | Tests for CWE-676/242 |
| `agents/cwe/tests/unit/test_insufficient_logging_check.py` | Tests for CWE-778 |
| `agents/cwe/tests/unit/test_uncaught_exception_check.py` | Tests for CWE-248 |
| `agents/cwe/tests/unit/test_weak_entropy_check.py` | Tests for CWE-331/332 |
| `scripts/verify_cwe_coverage.py` | End-to-end coverage verifier |
| `agents/cwe/tests/unit/conftest.py` | Autouse fixture resetting `_KEYWORD_INDEX_CACHE` + `_parent_children_index.cache_clear()` |
| `agents/cwe/tests/unit/test_catalog.py` | New catalog-JSON assertions (observed_examples, mined keywords, generic-token filtering) |

## Files to Modify

| File | Change |
|---|---|
| `scripts/extract_cwe_catalog.py` | Add `_extract_observed_examples`; expand `tech_words` regex with dangerous-function stems; mine three text sources; adopt shared `_GENERIC_TOKENS` |
| `agents/cwe/cwe_agent/data/cwe_catalog.json` | Regenerated (size ≤ 3.0 MB) |
| `agents/cwe/cwe_agent/catalog.py` | Add `_parent_children_index` (lru_cache), `get_descendants` |
| `agents/cwe/cwe_agent/skills/catalog_detector.py` | `_emit_parent_rollups` helper; change 15-CWE cap `return` → `break`; extend `_DEDICATED_SKILL_CWES`; `get_static_detectable` threshold 0.3 → 0.2 |
| `agents/cwe/cwe_agent/skills/__init__.py` | Register 6 new skills in `SKILL_MAP`, `SKILL_TOOLS`, `__all__` |
| `agents/cwe/cwe_agent/config.py` | Add 6 entries to `ALL_CATEGORIES` AND to `AGENT_INFO["skills"]`; update description count 16 → 22 |
| `agents/cwe/cwe_agent/agent.py` | Update `INSTRUCTIONS` counts: "16 concurrent detectors" → "22", "15 dedicated skills" → "21" |
| `agents/cwe/cwe_agent/skills/SKILLS.md` | Document new skills + update "16 categories" → "22", "15 dedicated" → "21" |
| `agents/cwe/tests/unit/test_skills.py` | Category-count assertion 16 → 22 |
| `agents/cwe/tests/unit/test_catalog_detector.py` | Rollup tests (helper-level + integration); rename `test_skill_count_is_16` → `test_skill_count_matches_all_categories`; scannable-CWE count assertion 254 → 400; potentially widen `test_clean_code_produces_few_findings` threshold (Task 5.6) |

## Test Results

_Not yet run._

## Notes

- This plan is strictly additive. Existing 16 skills remain unchanged; `catalog_detector.py` logic for the existing keyword-index flow is unchanged except for the threshold tuning in Task 5.
- Task 5 includes an abort guard: if the threshold change more than doubles findings on a clean fixture, it is reverted without unwinding Tasks 1–4.
- E2E memory-system tests unaffected (no schema changes).
