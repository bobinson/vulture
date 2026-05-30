# 0048 — Implementation status

**Last updated**: 2026-05-27
**State**: IMPLEMENTED + REVIEWED + E2E-VERIFIED — ready for merge

## Checklist

- [x] Feature folder + plan/status/rollback docs
- [x] `backend/pkg/pluginregistry/plugin.go` (types)
- [x] `backend/pkg/pluginregistry/manifest.go` (TOML parsing + validation)
- [x] `backend/pkg/pluginregistry/virtual.go` (synthesise in-tree manifests)
- [x] `backend/pkg/pluginregistry/loader.go` (filesystem discovery)
- [x] `backend/pkg/pluginregistry/state.go` (state.toml)
- [x] `backend/pkg/pluginregistry/registry.go` (Registry interface + singleton)
- [x] `backend/pkg/pluginregistry/*_test.go` — 24 tests, all pass
- [x] `BurntSushi/toml v1.4.0` added to go.mod
- [x] Plan revision: `agentregistry/registry.go` is **not** refactored to a facade
      (cleaner: pluginregistry imports agentregistry to build virtuals)
- [x] `internal/server/server.go` wires `pluginregistry.Default()` at boot
- [x] `go build ./...` clean
- [x] `go test ./...` — all packages pass, including pre-existing agentregistry tests

## Test summary

```
pkg/pluginregistry  39 tests  PASS (race detector clean)
  - 24 original (manifest/loader/registry/virtual + state roundtrip)
  - 15 added during audit fixes:
      validation parity (scan/discover/validate required emits, enums
      for emits/languages/networks, length caps, ack uniqueness,
      network=host+egress-ack, host-binary port range, in-tree-tier
      reverse sanity check), symlink rejection, atomic SaveState,
      Default() concurrent build CAS, ResetDefault rebuild path,
      state-load fallback, bad state-path handling
pkg/agentregistry    5 tests  PASS (unchanged)
internal/server      6 tests  PASS (server.New now builds a registry; NewWithRegistry for tests)
... full backend     all      PASS under -race
```

## Code review + fix pass

A code-reviewer agent surfaced 14 findings (3 BLOCKERs, 4 MAJORs, 4 MINORs, 3 NITs)
against the initial implementation. All 14 were fixed in this session.
Highlights:

- **BLOCKER #1** — Data race in `Default()`/`ResetDefault()` resolved by switching from
  `sync.Once + sync.Mutex` to `atomic.Pointer[Registry]` with CAS-based first-build-wins.
- **BLOCKER #2** — `ValidateManifest` now enforces schema `allOf` per-phase required
  emits (scan→finding, discover→discover_result, validate→validation_update).
- **BLOCKER #3** — `emits` enum membership now enforced (19 legal event names).
- **MAJOR #6** — `SaveState` is now atomic (write `.tmp` sibling + `os.Rename`),
  preventing the empty-file-on-encode-failure data loss class.
- **MAJOR #7** — `server.New` now builds its own registry via `pluginregistry.Build`
  per call; `NewWithRegistry` exposed for test injection. Removes the global
  singleton from the hot path; `Default()` remains only as a top-level convenience.
- **MINOR #10** — Symlinked `plugin.toml` files are now refused via `os.Lstat`
  (verified with /etc/passwd symlink in T4).

## End-to-end test results (T1–T6)

```
PASS: T1 cold start lists 10 in-tree
PASS: T1 state.toml created
PASS: T1 state.toml mode 0600
PASS: T2 with valid external (11 plugins)
PASS: T3 malformed manifest skipped with warning
PASS: T3 valid sibling still loaded
PASS: T4 symlinked plugin.toml rejected ("refusing to follow symlinked")
PASS: T4 attacker plugin not registered (still 10 plugins)
PASS: T5 disabled state in state.toml honored (10/11 enabled)
PASS: T6 GET /api/agents returns 200, 10 agents (no regression on legacy path)
```

## What ships

- A read-only `Registry` interface with `All() / Enabled() / ByName()`.
- Virtual manifests for the 10 existing in-tree agents.
- Filesystem discovery from `~/.vulture/plugins/*/plugin.toml`.
- Test/packaging override via `VULTURE_PLUGIN_DIRS`.
- `state.toml` for per-plugin enable/disable.
- Strict load-time validation rejecting malformed manifests with a
  log warning (does not crash backend).
- Sanity check: a third-party manifest cannot claim
  `runtime.type=in-tree`.

## What's deferred

- **0049 — Stage Router**: capability-based dispatch. Until then,
  audit dispatch continues to use `cfg.Agents` (the legacy path).
- **0050 — CWE Normalisation**: the `[normalization]` block is
  parsed into a struct but no rules are applied.
- **0051 — Plugin CLI**: `vulture plugin install/list/disable`. For
  now, operators edit `state.toml` directly.
- Cosign verification — gated to 0051.

## Manual smoke (suggested before merge)

1. Start backend cold (no `~/.vulture/plugins`): expect log line
   `plugin registry: 10 plugins (10 enabled)` and a fresh
   `~/.vulture/plugins/state.toml`.
2. Drop a copy of `docs/spec/plugin-v1/examples/external-semgrep.toml`
   into `/tmp/plugins/semgrep/plugin.toml`,
   `VULTURE_PLUGIN_DIRS=/tmp/plugins vulture serve`: expect
   `11 plugins`.
3. Drop an intentionally malformed manifest: expect a `[plugin] skip
   /tmp/plugins/bad/plugin.toml: …` warning and the other plugins
   still loaded.
