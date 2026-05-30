# 0049 — Rollback plan

## Conditions warranting rollback

- An audit that worked before 0049 produces empty findings or a
  truncated set after 0049 — i.e. the new dispatch loses agents.
- The router crashes on a manifest the registry happily accepts
  (parity bug between 0048 validation and 0049 routing assumptions).
- Prove dispatch sends an unintended subset of findings to a plugin,
  hiding real CWE matches.
- External plugin URL resolution leaks `cfg.Agents` config to an
  external endpoint (security regression).

## Rollback procedure

### Phase A: feature-flag rollback (no revert)

While the `VULTURE_STAGE_ROUTER=true` flag is still in the code,
flip it back to `false` (the default) and restart. Old dispatch
restored instantly, no code changes needed. This is the primary
recovery mechanism during the side-by-side period.

### Phase B: post-flag-removal revert

After the flag is removed and 0049 is the only path, recovery
requires `git revert <0049-merge-sha>`:

1. `git revert <0049-merge-sha>` — restores the legacy
   `audit.Types`-based dispatch in stream + pipeline services.
2. `go mod tidy` — no new dependencies, nothing to drop.
3. Restart backend. Verify the old log line `[stream-svc]
   launching agent=…` reappears.
4. No data migration. The plugin registry (0048) keeps working
   read-only; nothing in the database depends on routing.

## Forward-fix instead of revert

Most failure modes are patchable:

| Failure | Patch |
|---|---|
| Router skips a legitimate plugin | inspect match rule; relax filter (e.g. treat empty `Languages` as "any") |
| Wrong findings sent to prove | check `matches_cwe` against the actual finding category strings; may need CWE normalisation (0050) to land first |
| External URL unreachable | document operator override `VULTURE_AGENT_<NAME>_URL` |
| Router race / panic | the package is pure logic — add a `defer recover` in `Route` and log + return empty |

Prefer forward-fix; the flag-flip in Phase A is fast enough that a
hard revert should only happen for security regressions.
