# 0051 — Rollback plan

## Triggers

- CLI install corrupts `state.toml` → atomic-rename pattern means the
  prior state.toml is preserved; forward-fix.
- Cosign integration produces false negatives blocking legitimate
  installs → bypass via `VULTURE_COSIGN_BINARY=/path/to/yes-binary`
  while the issue is investigated.
- Interactive prompt eats stdin in unexpected ways → operators can
  pass `--yes` to skip; CLI still records acks.
- Full revert: `git revert <0051-merge-sha>` removes the CLI
  surface; the registry continues working read-only as in 0048-0050.
  Marker files left behind are unreferenced and harmless.

## No data migration

No database changes. `state.toml` schema is unchanged from 0048 —
only field population semantics change. Old state.toml files
written before 0051 continue to load.
