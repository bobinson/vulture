# 0047 — Rollback plan

## Summary

This feature is **doc + schema + lint tool only**. No runtime code
changes, no database changes, no API changes, no user-visible behaviour
changes. Rollback is `git rm -r`.

## Why rollback might be needed

- The contract turns out to be wrong (premature lock-in of a field
  name; a phase abstraction that doesn't fit; CWE normalisation that's
  too strict).
- A downstream feature (0048+) discovers a contract clause that can't
  be implemented and we want to revise rather than patch.

## Rollback procedure

```bash
git rm -r docs/spec/plugin-v1/
git rm -r docs/features/0047_plugin_contract_spec/
git rm -r tools/plugin_lint/
# Revert the two cross-link patches:
git checkout HEAD~1 -- CONTRIBUTING.md agents/shared/SKILLS.md
git commit -m "Revert(0047): plugin contract spec — to be revised"
```

That's the complete rollback. No data loss possible. No coordination
with running services required.

## Partial rollback (revise without delete)

If only specific clauses are wrong:

- **Manifest schema wrong**: edit `manifest.schema.json` + bump
  `$schema` filename version (e.g. `manifest.schema.v1.1.json`).
  Keep old schema for examples that haven't migrated.
- **Event schemas wrong**: same pattern — version per file.
- **Spec text wrong**: edit `contract.md`. Note the change at the top
  of the file with a `## Changelog` section.

The spec is in `docs/`; iteration cost is one PR.

## Forward incompatibility

If we need to break the contract (e.g. the manifest schema needs a
field renamed and the field is mandatory for downstream features),
bump `api_version` in the spec from `1.0` to `2.0`. Old plugins are
not loaded by orchestrators that only support `2.x`. Migration:

1. Publish `vulture-plugin/2.0` spec under
   `docs/spec/plugin-v2/contract.md`.
2. Mark `v1` as `deprecated_at: <date>` in `contract.md`.
3. Ship a compatibility shim in the future registry (0048) that
   transforms v1 manifests to v2 internally where the transform is
   safe.
4. Communicate the deprecation timeline (≥ 6 months) in
   `CONTRIBUTING.md` and release notes.

## What does NOT need to roll back

- The existing 10 agents — they don't reference the spec at runtime,
  only at write-up time. They keep functioning identically.
- The validate phase (features 0045/0046).
- Any database migration.
- Any configuration changes.

## Acceptance criteria for successful rollback

- `docs/spec/plugin-v1/` removed (or specific files removed if partial).
- `tools/plugin_lint/` removed.
- `CONTRIBUTING.md` no longer references plugin spec.
- `git grep -E 'vulture-plugin/1\.0'` returns no in-tree code matches
  (only commit message history).
- All existing tests still pass: `make test`.

## What we keep even on full rollback

- Lessons-learned notes (if any) in `docs/features/0047_plugin_contract_spec/0047_implementation_status.md`
  before deletion. Useful for the next attempt at the same contract.
