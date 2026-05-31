# 0050 v1.1 — Implementation status

**Last updated**: 2026-05-29
**State**: COMPLETE — LLD reviewed (11 findings, 3 BLOCKERs incorporated); RED→GREEN TDD via subagents; live vulture-on-vulture E2E PASS (12/12 real Semgrep rule IDs resolve through the bundled-plugin discovery path).

## Checklist

- [x] LLD doc (this dir)
- [x] Cross-cutting review (correctness / reliability / maintenance / community / performance / security / DRY)
- [x] 11 findings incorporated (3 BLOCKER + 5 MAJOR + 3 MINOR/NIT)
- [x] RED phase via subagent — 17 test cases, production unchanged, fails at expected new symbols
- [x] GREEN phase via subagent — `loader.go` (+ helpers) + exported `MaxNormalisationEntries` + `CWERe`; gocyclo all <10
- [x] `go test -race ./...` clean across 22 packages
- [x] Bundled Semgrep `rules/rule_to_cwe.json` inflated from empty → 50 real entries
- [x] Bundled Semgrep `plugin.toml` declares `mapping_file = "rules/rule_to_cwe.json"`
- [x] Live E2E via `cmd/e2e_0050_v1_1`: 12/12 expectations PASS

## Findings applied

| # | Sev | Resolution |
|---|---|---|
| 1 | BLOCKER | sibling-dir traversal bypass | `manifestDir + string(filepath.Separator)` prefix + `filepath.Rel` cross-check |
| 2 | BLOCKER | `os.ReadFile` vs `io.LimitReader` incompatibility | `os.ReadFile` + post-read length check (16 MiB cap before JSON parse) |
| 3 | BLOCKER | all-or-nothing destroys 9999 valid entries | per-entry log+skip; summary line reports `loaded N/T (S skipped)` |
| 4 | MAJOR | intermediate symlinks bypass `os.Lstat` | `filepath.EvalSymlinks` + divergence check |
| 5 | MAJOR | `MaxNormalisationEntries` duplicated by comment | exported, imported by loader (single source of truth) |
| 6 | MAJOR | untestable failure modes | `loadMappingFile` returns `(map, error)` with 9 typed sentinels |
| 7 | MAJOR | `mapping_file = ""` semantics undefined | `strings.TrimSpace` + silent no-op for empty/whitespace |
| 8 | MAJOR | Semgrep YAML conversion workflow missing | LLD documents JSON-only contract + conversion-script reference |
| 9 | MINOR | `CWERe` cycle reasoning inverted | exported, loader uses the shared regex |
| 10 | MINOR | redundant traversal checks not differentiated | clarified: `RejectTraversal` for raw input; prefix check for post-clean |
| 11 | NIT | `defer recover` requires named return | dropped (encoding/json doesn't panic) |

## Test results

```
internal/cwe                14 loader tests + 4 integration tests   PASS (race clean)
pkg/pluginregistry          2 exported-constant tests + existing    PASS
... full backend            22 packages PASS under -race
```

## Live E2E (vulture source itself)

```
$ VULTURE_BUILTIN_PLUGINS_DIR=$REPO_ROOT/plugins \
    go run ./cmd/e2e_0050_v1_1

registered: semgrep tier=in-tree source=builtin
  PASS  python.django.security.audit.xss.template-autoescape-off          -> CWE-79
  PASS  python.lang.security.audit.dangerous-system-call                  -> CWE-78
  PASS  python.lang.security.audit.weak-md5-algorithm                     -> CWE-328
  PASS  python.cryptography.fernet                                        -> CWE-310
  PASS  go.lang.security.audit.dangerous-exec-command                     -> CWE-78
  PASS  go.lang.security.audit.tls.tls-skip-verify                        -> CWE-295
  PASS  javascript.express.security.audit.xss.template-explicit-injection -> CWE-79
  PASS  javascript.jwt.security.jwt-hardcode-secret                       -> CWE-798
  PASS  java.spring.security.web.cors-csrf                                -> CWE-352
  PASS  java.lang.security.audit.formatted-sql-string                     -> CWE-89
  PASS  inline+external agree on python.django.security.unsafe-raw-sql -> CWE-89
  PASS  unknown rule returns empty CWE

Resolved 12 of 12 expectations
E2E PASS
```

This is the strongest version of vulture-on-vulture: Vulture's
production registry loads Vulture's own bundled Semgrep plugin
from `VULTURE_BUILTIN_PLUGINS_DIR=plugins`, Vulture's own CWE layer
loads the bundled `rules/rule_to_cwe.json`, and Vulture resolves
real Semgrep rule IDs to canonical CWE values. The full stack works.

## Files shipped

```
backend/internal/cwe/loader.go                      NEW (loadMappingFile + 9 sentinels)
backend/internal/cwe/loader_test.go                 NEW (RED, 14 tests)
backend/internal/cwe/layer.go                       MOD (merges external entries)
backend/internal/cwe/layer_test.go                  MOD (+4 integration tests)
backend/pkg/pluginregistry/manifest.go              MOD (export MaxNormalisationEntries + CWERe)
backend/pkg/pluginregistry/manifest_strict_test.go  MOD (call-site renames)
backend/pkg/pluginregistry/manifest_test.go         MOD (+2 exported-constant tests)
backend/cmd/e2e_0050_v1_1/main.go                   NEW (live vulture-on-vulture)
plugins/semgrep/plugin.toml                         MOD (declare mapping_file)
plugins/semgrep/rules/rule_to_cwe.json              MOD (empty → 50 real entries)
docs/features/0050_cwe_normalization_v1_1/*.md      NEW
```

## Open residuals (deliberate)

- **Schema version 2+**: only `"1"` accepted in v1.1. v1.2 may add `"2"` if/when the format needs an extension.
- **Multi-file mapping**: one `mapping_file` per plugin in v1; globs like `rules/*.json` are a future v1.2 item if a plugin needs language-split files.
- **Remote fetching**: deliberately not in scope. Local files only.
- **Conversion tooling**: ✓ shipped 2026-05-29 at `plugins/semgrep/tools/semgrep_rules_to_cwe.py` (16 unit tests + README). Plugin authors regenerating `rules/rule_to_cwe.json` from upstream Semgrep packs no longer need to hand-curate.
