# 0048 — Rollback plan

## Conditions warranting rollback

- Backend fails to start with an empty `~/.vulture/plugins/` directory.
- A malformed local manifest crashes the backend instead of being skipped.
- An existing in-tree agent (chaos, owasp, soc2, cwe, etc.) disappears
  from `GET /api/agents` after the registry refactor.
- `agentregistry.AllAgents` no longer enumerates the same 10 in-tree
  agents (regression in any consumer that loops over it).

## Rollback procedure

1. `git revert <0048-merge-sha>` — single revert restores the prior
   static slice + removes the `pluginregistry` package.
2. `go mod tidy` — drop the `BurntSushi/toml` dependency.
3. Restart the backend; verify `GET /api/agents` returns the 10 legacy
   agents.
4. No data migration required — the registry is read-only and stores
   nothing in the database. The optional `~/.vulture/plugins/state.toml`
   file can be left in place or deleted by the operator.

## Forward-fix instead of revert

Most failure modes can be patched without revert:

| Failure | Patch |
|---|---|
| Malformed manifest crashes | wrap the offending parser in `defer recover` and skip |
| In-tree agent missing | the virtual-manifest synthesiser is the only path; add the missing field to the synthesiser |
| State file permissions block startup | fall back to in-memory state with a warning |

Prefer forward-fix; reserve revert for cases where the bug surface is
larger than the package itself.
