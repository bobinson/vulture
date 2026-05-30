# 0050 v1.1 — Rollback plan

## Triggers

- Loader bug causes Layer.New panics → defensive: the LLD pinned no
  `defer recover` (encoding/json doesn't panic; sentinel errors
  cover the rest). If a panic surfaces anyway, wrap `loadMappingFile`
  in a `defer recover` at the Layer.New call site and skip the plugin.
- Bad data in `plugins/semgrep/rules/rule_to_cwe.json` → data-only
  PR. Per-entry skip already protects against single-entry errors.
- Operator's external file is malformed / oversized / mistyped →
  graceful degradation by design (Layer.New logs and continues with
  inline-only entries; plugin stays usable).
- Full revert: `git revert <0050-v1.1-merge>`. `mapping_file` reverts
  to "parsed-and-ignored" as in 0050 v1; Semgrep manifest's
  `mapping_file` line reverts. No DB changes. `MaxNormalisationEntries`
  and `CWERe` exports revert with the same commit.

## No data migration

Loader is read-only from disk + manifests. No state.toml or DB schema
changes. Operators who had `mapping_file` declared but couldn't read
it (0050 v1) keep working post-revert just as they did before.
