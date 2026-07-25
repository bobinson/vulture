# 0048 — Dynamic plugin registry

**Author**: tbd
**Status**: IMPLEMENTED — awaiting review
**Created**: 2026-05-27
**Depends on**: feature 0047 (plugin contract spec)
**Unblocks**: 0049 (stage router), 0050 (CWE normalisation), 0051 (CLI),
              0053 (Semgrep plugin)

## Goal

Replace the static `backend/pkg/agentregistry/registry.go:AllAgents`
slice with a runtime registry that discovers plugins from manifest
files. The existing 10 in-tree agents continue to work unchanged via
auto-synthesised virtual manifests.

## Why

`agentregistry.AllAgents` is the single choke point preventing third-
party plugins. Every new agent today requires editing a Go file +
docker-compose + frontend. The plugin contract (feature 0047) only
becomes useful once something *reads* manifests at runtime. This
feature implements that reader.

After 0048, an operator can:

```bash
cp my-plugin.toml ~/.vulture/plugins/my-plugin/plugin.toml
# restart backend
```

…and the plugin is registered, visible on `GET /api/agents`, and
dispatchable by name.

## Non-goals

- **Stage / capability matching** — 0049 owns this. 0048 keeps the
  legacy "match by `audit.Types`" dispatch path.
- **CWE normalisation engine** — 0050 owns this. 0048 reads the
  `[normalization]` block into a Go struct but doesn't apply rules.
- **CLI install / disable** — 0051 owns this. 0048 supports manually
  dropping manifests + a `state.toml` for enable/disable, but
  has no command-line surface.
- **Cosign verification** — 0051. Manifests with `tier=community-signed`
  are accepted as-is in 0048 with a startup warning.
- **Hot reload** — restart the backend to pick up new plugins.

## Deliverables

| File | Purpose |
|---|---|
| `backend/pkg/pluginregistry/plugin.go` | `Plugin`, `Capability`, `TrustBlock` types |
| `backend/pkg/pluginregistry/manifest.go` | TOML parsing + schema validation |
| `backend/pkg/pluginregistry/virtual.go` | Synthesise manifests for in-tree agents |
| `backend/pkg/pluginregistry/loader.go` | Filesystem discovery |
| `backend/pkg/pluginregistry/state.go` | `state.toml` read/write |
| `backend/pkg/pluginregistry/registry.go` | `Registry` interface + impl |
| `backend/pkg/pluginregistry/*_test.go` | Unit + integration tests |
| `backend/pkg/pluginregistry/testdata/*.toml` | Test fixtures |
| `backend/pkg/agentregistry/registry.go` | Refactor to thin facade over pluginregistry |
| `backend/go.mod`, `go.sum` | `github.com/BurntSushi/toml` added |

Lines of code: ~600 net.

## Architecture

```
                 ┌─ in-tree (synthesised from AllAgents)
PluginRegistry  ─┼─ local  (~/.vulture/plugins/*/plugin.toml)
                 └─ env override (VULTURE_PLUGIN_DIRS for tests / packaging)
                                                ▼
                                  []Plugin (in-memory, immutable)
                                                ▼
              ┌── agentregistry.AllAgents (legacy facade)
   consumed by─── handler/* (GET /api/agents)
              └── stream_service / audit dispatch
```

### Sources of plugin manifests

1. **Virtual** — for each entry in the legacy `AllAgents` slice, the
   loader synthesises a minimal manifest with `tier=in-tree`,
   `runtime.type=in-tree`. Preserves today's behaviour exactly.
2. **Local plugin directory** — `~/.vulture/plugins/<name>/plugin.toml`.
3. **Env override** — colon-separated list in `VULTURE_PLUGIN_DIRS`
   for tests + air-gapped deployments. Each entry can be a directory
   (scanned recursively for `plugin.toml`) or a direct file path.

Conflicts (same plugin name from two sources): in-tree wins.
Local-vs-env: env wins (operator can override).

### State persistence

`~/.vulture/plugins/state.toml` (created on first registry start if
absent):

```toml
[plugins.cwe]
enabled = true
trust_acks = []
installed_at = "2026-05-27T..."

[plugins.semgrep]
enabled = true
trust_acks = []
installed_at = "2026-05-27T..."
```

Default state for a newly-discovered plugin is `enabled=true`.
Operators can edit `state.toml` to disable a plugin without
uninstalling. (The 0051 CLI will provide a friendlier interface.)

### Backwards compatibility

`agentregistry` is left untouched — it remains the literal source of
truth for in-tree agents. `pluginregistry` imports it to synthesise
virtual manifests. This avoids a circular-dependency risk and means
every existing consumer (config, agui translator, agent handler,
localdev) continues to compile and pass tests with no change.

| Today's API | After 0048 |
|---|---|
| `agentregistry.AllAgents []AgentRegistryEntry` | **Unchanged**: still a literal slice. |
| `agentregistry.ScanAgentTypes()` | **Unchanged**. |
| `agentregistry.AllScanAgentTypes()` | **Unchanged**. |
| `agentregistry.EnvURLKey(t)` | **Unchanged**. |
| `GET /api/agents` response shape | **Unchanged**. |
| Existing tests | All pass. |
| `pluginregistry.Default()` | NEW — process-wide singleton, built at server.New. |

## Acceptance criteria

1. Backend starts cleanly with **no plugins installed** — discovers
   10 virtual manifests for the existing in-tree agents.
2. Backend starts cleanly with a **valid local plugin** at
   `~/.vulture/plugins/foo/plugin.toml` — discovers 11 plugins total.
3. Backend starts cleanly with an **invalid local plugin** (malformed
   TOML, schema violation) — logs a warning, skips that plugin, doesn't
   crash. Other plugins remain usable.
4. `agentregistry.AllAgents` returns the same 10 in-tree entries as
   before 0048 (verified by existing tests).
5. `state.toml` is created on first start with `enabled=true` for all
   discovered plugins.
6. Editing `state.toml` to set `enabled=false` for an agent → that
   agent's manifest still appears in the registry but with
   `.Enabled == false` (consumers can filter).
7. `VULTURE_PLUGIN_DIRS=/tmp/test-plugins` allows loading test plugins
   from a custom directory.
8. Existing audit flow (POST /api/audits, SSE stream) works
   unchanged.

## Implementation order

1. Feature docs (plan / status / rollback).
2. Type definitions (`plugin.go`).
3. TOML parsing tests + impl (`manifest.go`).
4. Virtual manifest generator tests + impl (`virtual.go`).
5. Filesystem loader tests + impl (`loader.go`).
6. State file tests + impl (`state.go`).
7. Registry interface + impl + tests (`registry.go`).
8. Refactor `agentregistry/registry.go` to facade.
9. Add `BurntSushi/toml` to go.mod.
10. Run full test pyramid; verify no regressions.

## Files touched

| File | Action |
|---|---|
| `docs/features/0048_dynamic_plugin_registry/*.md` | NEW (3 files) |
| `backend/pkg/pluginregistry/plugin.go` | NEW |
| `backend/pkg/pluginregistry/manifest.go` | NEW |
| `backend/pkg/pluginregistry/virtual.go` | NEW |
| `backend/pkg/pluginregistry/loader.go` | NEW |
| `backend/pkg/pluginregistry/state.go` | NEW |
| `backend/pkg/pluginregistry/registry.go` | NEW |
| `backend/pkg/pluginregistry/plugin_test.go` | NEW |
| `backend/pkg/pluginregistry/manifest_test.go` | NEW |
| `backend/pkg/pluginregistry/loader_test.go` | NEW |
| `backend/pkg/pluginregistry/registry_test.go` | NEW |
| `backend/pkg/pluginregistry/testdata/*.toml` | NEW (3-5 fixtures) |
| `backend/pkg/agentregistry/registry.go` | **unchanged** (revised plan: pluginregistry imports it, no facade refactor needed) |
| `backend/internal/server/server.go` | wire `pluginregistry.Default()` into `New()` |
| `backend/go.mod`, `go.sum` | add `BurntSushi/toml` |

## Security hardening

- **SH1**: manifest path traversal — `mapping_file` paths in
  `[normalization]` blocks must be inside the plugin's own directory
  or be absolute paths the operator explicitly trusts. Defer
  enforcement to 0050 (CWE normalisation engine).
- **SH2**: TOML parser is `BurntSushi/toml` v1.4.0 (latest stable);
  it has no known vulnerabilities and is widely audited.
- **SH3**: state.toml is created with mode 0600 (operator-private).
- **SH4**: invalid manifests don't crash — they're logged and skipped.
  A poisoned third-party plugin can't take down the backend by
  shipping bad TOML.

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| TOML parsing on every backend start adds latency | Manifests are < 5 KB; total parse time for 10–20 plugins is ~10 ms. Negligible. |
| Existing tests rely on `AllAgents` being a literal slice | The facade preserves the slice type and contents. Verified by running the existing `agentregistry_test.go`. |
| Local plugin manifests with the same name collide | First-discovered wins; the loader logs a `[plugin] duplicate name '%s' from %s — keeping %s` warning. |
| New TOML dependency widens the attack surface | BurntSushi/toml is single-file, no transitive deps, audited. Pinned in go.mod. |
