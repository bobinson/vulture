# 0049 — Implementation status

**Last updated**: 2026-05-28
**State**: COMPLETE — every acceptance criterion (1-8) verified; deferred pipeline refactor landed; synthetic-plugin end-to-end SSE roundtrip exercised. **`VULTURE_STAGE_ROUTER` feature flag removed 2026-05-29** after clean shipping through 0050/0051/0052/0053. The router is now the default whenever a non-nil registry is wired; nil-router fallback remains as documented degraded-mode behaviour.

## Checklist

- [x] Feature folder + plan/status/rollback docs
- [x] LLD review pass (12 findings; 4 BLOCKERs, 5 MAJORs, 3 MINORs/NITs)
- [x] BLOCKERs / MAJORs incorporated into the design before code:
  - PriorFinding (not Finding) in RouteRequest
  - Catch-all on empty matchers is **in-tree only**
  - Empty-string prefix rejected (no SH2 bypass)
  - `URLResolver` extracted as an injectable interface
  - Env vars win over config.ini (twelve-factor)
  - Env snapshot taken once at construction (no I/O in `Route()`)
  - `ValidateEnabled` flag gates validate stage
- [x] `backend/pkg/stagerouter/router.go` (Router interface + impl)
- [x] `backend/pkg/stagerouter/match.go` (per-stage match rules)
- [x] `backend/pkg/stagerouter/url.go` (URLResolver + default impl)
- [x] `backend/pkg/stagerouter/*_test.go` — 17 unit tests, all pass under `-race`
- [x] `backend/internal/service/stream_service.go` refactor — feature-flag gated
- [x] `backend/internal/service/stream_service_router_test.go` — 3 integration tests, pass under `-race`
- [x] `backend/internal/server/server.go` wires router into stream service
- [x] `VULTURE_STAGE_ROUTER=true` feature flag controls the rollout (REMOVED 2026-05-29 after parity proven across 0050-0053)
- [x] Full backend `go test -race ./...` clean
- [x] E2E: T1–T4 against rebuilt binary, all pass

## Scope deviation from plan — RESOLVED

The `pipeline_service.stageAuditTypes` refactor was initially deferred
but landed in a follow-up commit. The pipeline's default scan stage
now unions the in-tree default set with enabled external scan
plugins via `stagerouter.DefaultScanAgentTypes(registry, base)`.

What changed:

- `stagerouter.DefaultScanAgentTypes(registry, base)` — new helper
  that takes the in-tree baseline (still produced by
  `agentregistry.ScanAgentTypes()` so Optional + pipeline-stage
  filters are honoured) and appends Enabled non-in-tree plugins with
  at least one scan-phase capability. Preserves registry order, no
  duplicates.
- `service.NewPipelineServiceWithScanTypes(repo, auditSvc,
  discoverSvc, defaultScanTypes func() []string)` — new constructor
  accepting an injected provider. Legacy `NewPipelineService`
  delegates to this with `config.ScanAgentTypes` as the provider.
- `pipeline_service.stageAuditTypes` becomes a method that calls
  `s.defaultScanTypes()` when no explicit `types` are set in the
  pipeline config.
- `server.New` injects a closure that calls
  `stagerouter.DefaultScanAgentTypes(reg, config.ScanAgentTypes())`
  so external plugins automatically participate in pipeline-driven
  scans.

E2E verification: a pipeline created with no explicit `types` against
a backend with one external user-supplied scan plugin produced an
audit with `Types = [chaos, owasp, soc2, cwe, xss, ssdf, asvs,
example-ext]` — in-tree defaults plus the external plugin, with
`prove`/`discover` correctly excluded.

## Test summary

```
pkg/stagerouter        17 tests  PASS (race detector clean)
  - 12 unit tests on Route() per-stage rules + multi-capability
  - 5 unit tests on URLResolver precedence + env snapshot
internal/service       +3 tests  PASS
  - StreamService_RouterDisabledWhenFlagOff (legacy fallback)
  - StreamService_RouterDispatchUsesRegistry (router path)
  - StreamService_RouterDedupsMultiCapability (MAJOR #9 dedup)
internal/server         no changes (router wiring only)
... full backend       all PASS under -race
```

## LLD-review fix map

| # | Severity | Issue | Resolution |
|---|---|---|---|
| 1 | BLOCKER | empty-string prefix bypass | `hasNonEmptyPrefix` helper rejects `[""]` → falls through to in-tree-only catch-all |
| 2 | BLOCKER | catch-all unsafe for non-in-tree tiers | `matchCapability` checks `p.Manifest.Trust.Tier == TierInTree` before catch-all |
| 3 | BLOCKER | `RouteRequest.PriorFindings` wrong type | uses `model.PriorFinding` (lightweight) — never the heavy `Finding` |
| 4 | BLOCKER | TDD ordering critique | unit tests written tandem with each component; integration tests after stream refactor |
| 5 | MAJOR | discover bootstrap (empty TechStacks) | documented as intentional in `match.go`; `TestRoute_DiscoverEmptyTechStacks_DispatchesAll` |
| 6 | MAJOR | validate stage ignored L1-L5 gate | added `RouteRequest.ValidateEnabled`; off by default; `TestRoute_ValidateGatedByFlag` |
| 7 | MAJOR | env should win over config.ini | inverted precedence in `defaultResolver.Resolve`; `TestResolveURL_EnvWinsOverConfig` |
| 8 | MAJOR | `os.Getenv` on every Route call | `snapshotEnvURLs()` runs once in `NewURLResolver`; `TestSnapshotEnvURLs_ExtractsAndNormalises` |
| 9 | MAJOR | multi-capability test gap | router emits one target per matched capability; stream service dedupes by `PluginName`; tested in both layers |
| 10 | MAJOR | URLResolver as separate interface | extracted; `NewWithResolver` accepts an injectable resolver |
| 11 | MINOR | `setStageAuditID` missing validate branch | flagged for the deferred pipeline refactor |
| 12 | NIT | feature-flag read once per audit | confirmed: `useRouter()` is called once at the top of `StreamWithContext` |

## End-to-end test results (T1–T5)

```
PASS: T1 boot clean (router flag off)
PASS: T1 vulture started
PASS: T1 /api/agents 200
PASS: T2 boot clean (router flag on)
PASS: T2 /api/agents 200
PASS: T3 external plugin registered (11 plugins)
PASS: T4 boot clean with VULTURE_AGENT_EXAMPLE_EXT_URL set
PASS: T5 pipeline default scan includes external plugin
       (example-ext appears in audit.Types alongside chaos/owasp/...)
PASS: T6 synthetic plugin → router → real proxy → SSE roundtrip
       (finding + result events land in event channel as
       StateDelta + StateSnapshot containing the synthetic title)
PASS: T7 router allow-list at integration level — synthetic plugin
       NOT called when its name absent from audit.Types
```

## Out of scope / next steps

- Pipeline service refactor → follow-up after 0050
- CWE normalisation engine → 0050 (prove-stage routing depends on it)
- Plugin CLI → 0051
- Cosign verification → 0051
- Frontend "source" badge for in-tree vs external → cosmetic, separate PR
