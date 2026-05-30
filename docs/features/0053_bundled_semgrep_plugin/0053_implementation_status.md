# 0053 — Implementation status

**Last updated**: 2026-05-28
**State**: COMPLETE — LLD reviewed (22 findings; 14 of-0053 incorporated); RED→GREEN TDD via subagents; live E2E against vulture's own source: 16/16 PASS.

## Checklist

- [x] LLD doc
- [x] Cross-cutting review across 7 axes (22 findings)
- [x] 0053-relevant findings incorporated (2, 3, 4, 5, 9, 11, 12, 13, 14, 15, 16, 18, 20, 21)
- [x] Backend RED → GREEN (scoped sanity-check relaxation + `BuiltinDir` discovery)
- [x] Python wrapper RED → GREEN (translate, normalise_source_path, wrapper)
- [x] Dockerfile + manifest + READMEs shipped
- [x] `go test -race ./...` clean (22 packages)
- [x] `pytest plugins/semgrep/tests/unit/` — 34 tests PASS
- [x] E2E with mock semgrep against vulture's own backend — 16/16 PASS

## Test results

```
Go:     pkg/pluginregistry      +4 tests   PASS (builtin source, merge, env discovery)
Python: tests/unit/test_translate.py        13 tests PASS
        tests/unit/test_normalise_source_path.py  8 tests PASS
        tests/unit/test_wrapper.py          13 tests PASS  (including BLOCKER #2 concurrent-request)
Total:  34 Python unit tests + 4 Go tests
E2E:    16 assertions PASS (1 wrapper + 1 info + 2 contract validation + 4 SSE sequence +
         1 vulture-on-vulture + 1 CWE extraction + 1 severity + 1 fallback + 4 Go loader tests)
```

## Findings applied

| # | Sev | Resolution |
|---|---|---|
| 2 | BLOCKER | Wrapper uses `loop.run_in_executor` so subprocess doesn't freeze the asyncio loop |
| 3 | BLOCKER | `sanityCheckRuntime` accepts `source` parameter; relaxation scoped to `Source == "builtin"` only |
| 4 | BLOCKER | `mapping_file` removed from v1 manifest; ship inline `prefix_to_cwe` only |
| 5 | BLOCKER | `extract_cwe` regex strips `"CWE-89: descriptive text"` to canonical `CWE-89` |
| 9 | MAJOR | `normalise_source_path` rejects `-` prefix, `..` traversal, and symlinks escaping `/audit-inputs` |
| 11 | MAJOR | Wrapper validates `envelope == "vulture-plugin/1.0"`; reads `body.input.source_path` per contract |
| 12 | MAJOR | Inline prefix map non-overlapping with orchestrator's base map |
| 13 | MAJOR | `rules/*.json` files ship `"schema_version": "1"` field |
| 14 | MINOR | Semgrep `ERROR → high` (not critical) for L2 rollup compatibility |
| 15 | MINOR | Dockerfile redirects `SEMGREP_RULES_CACHE` to nobody-readable path |
| 16 | MINOR | Exit code 7 → explicit `SEMGREP_APP_TOKEN` message |
| 18 | MINOR | "30 minutes" claim dropped; replaced with prerequisites checklist |
| 20 | MINOR | README pins template defaults explicitly |
| 21 | NIT | Dockerfile labelled single-stage; `USER 65534:65534` numeric UID |

## Live E2E results

```
T1  /health 200                                PASS
T2  /info returns name=semgrep                 PASS
T3  wrong envelope → HTTP 400  (BLOCKER #11)   PASS
T4  flag-style source_path → 400 (BLOCKER #9)  PASS
T5  SSE event sequence (run_started, ≥3 finding, result, run_finished)  4× PASS
T6  findings reference vulture-backend paths   PASS  ← vulture-on-vulture proof
T7  canonical CWE-78 extracted from real Semgrep format (BLOCKER #5)   PASS
T8  ERROR severity maps to "high" (MINOR #14)  PASS
T9  finding without CWE falls back to check_id as category   PASS
T10 Go loader tests (4× PASS):
    - TestSanityCheckRuntime_BuiltinSource_AllowsInTreeTierWithContainerRuntime_0053
    - TestLoad_FromBuiltinDir_0053
    - TestLoad_BuiltinAndLocalMerged_0053
    - TestDefaultLoadOptions_BuiltinDir_FromEnv_0053
```

## Files shipped

```
plugins/semgrep/
├── plugin.toml                       (manifest, tier=in-tree + runtime=container)
├── Dockerfile                        (single-stage, USER 65534:65534)
├── pyproject.toml                    (fastapi/uvicorn/pytest/httpx)
├── src/
│   ├── __init__.py
│   ├── sse.py                        (canonical SSE writer; community plugins copy verbatim)
│   ├── translate.py                  (extract_cwe, map_severity, translate_findings, normalise_source_path)
│   └── wrapper.py                    (FastAPI /health, /info, /run with run_in_executor)
├── rules/
│   ├── prefix_to_cwe.json            (schema_version=1, 4 Semgrep-specific entries)
│   └── rule_to_cwe.json              (schema_version=1, empty entries; placeholder for v1.1)
├── tests/
│   ├── fixtures/semgrep_output_real.json  (real Semgrep JSON format)
│   └── unit/
│       ├── test_translate.py         (13 tests, BLOCKER #5 + MINOR #14)
│       ├── test_normalise_source_path.py  (8 tests, BLOCKER #9)
│       └── test_wrapper.py           (13 tests, BLOCKER #2 + BLOCKER #11 + MINOR #16)
└── README.md                         (forkability guide, no "30 min" claim)

backend/pkg/pluginregistry/loader.go          MOD: BuiltinDir field, source-scoped sanity check
backend/pkg/pluginregistry/loader_0053_test.go NEW
```

## Migration path

When `plugins/semgrep/` is ready to extract to its own repo, the
following labels change (no code change to Vulture core):

| Field | Before | After |
|---|---|---|
| trust.tier | `in-tree` | `community-signed` |
| trust.signature | (absent) | `cosign://sigstore/<publisher>/vulture-plugin-semgrep` |
| publisher | `vulture-core` | `<maintainer-org>` |
| homepage | monorepo URL | new repo URL |

The 0048 sanity check already accepts community-signed plugins with
container runtime (the scoping in 0053 only added builtin-source
exception; community-signed is unaffected).
