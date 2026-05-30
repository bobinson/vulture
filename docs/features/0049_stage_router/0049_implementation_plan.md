# 0049 — Stage Router with Capability Negotiation

**Author**: tbd
**Status**: PLAN (awaiting review)
**Created**: 2026-05-28
**Depends on**: 0047 (plugin contract), 0048 (dynamic plugin registry)
**Unblocks**: 0050 (CWE normalisation), 0051 (CLI), 0053 (Semgrep plugin)

## Goal

Replace the hard-coded `audit.Types`-based agent dispatch with a
**capability-based stage router** that consumes `pluginregistry`
manifests. The router decides, for each pipeline stage, which
plugins to invoke based on:

- the stage (scan / discover / prove / validate)
- the capability filters declared in each plugin's manifest
- the context for that stage (requested types, detected tech stacks,
  prior findings carrying CWE / check_id_prefix)

In-tree agents keep working unchanged through synthesised manifests
(feature 0048). External plugins become dispatchable for the first
time.

## Why now

After 0048, the registry knows what's installed but nothing reads
it for routing — the stream/pipeline services still iterate
`audit.Types` and look up `cfg.Agents[type]`. Until 0049 lands,
an external plugin like Semgrep has nowhere to plug in. 0049 is the
bridge between the registry and the existing audit pipeline.

## Scope

### In scope

1. `backend/pkg/stagerouter/` package — pure routing logic, no
   network I/O.
2. **DispatchTarget** struct carrying everything a downstream
   service needs to actually invoke a plugin: name, URL, phase,
   stage-config payload, capability metadata.
3. **Per-stage routing rules**:
   - `scan`: route to every enabled plugin with a scan capability,
     honouring the existing `audit.Types` filter (legacy behaviour)
     and language filters (`Capability.Languages`).
   - `discover`: route to plugins whose `tech_stacks` overlaps the
     context's detected tech stacks (or all discover plugins if no
     tech stacks specified — backwards compat).
   - `prove`: route to plugins whose `matches_cwe` /
     `matches_check_id_prefix` overlap with the prior findings
     supplied as context.
   - `validate`: route to every enabled validate plugin
     (filtering by selectors is deferred to a future feature).
4. **Runtime URL resolution**: prefer `cfg.Agents[name].URL` (legacy
   in-tree config.ini path), fall back to `VULTURE_AGENT_<NAME>_URL`,
   fall back to `http://agent-<name>:<port>` derived from the
   manifest. External plugins with `runtime.type=container` thus
   become reachable when an operator has the matching env var.
5. **Stream service refactor**: replace `audit.Types` iteration with
   `stagerouter.Route(...)`. Old behaviour preserved when no
   external plugins are installed.
6. **Pipeline service refactor**: `stageAuditTypes` becomes
   `stageDispatchTargets` and delegates to the router.
7. Tests + E2E.

### Out of scope (deferred)

- **CWE normalisation engine** — feature 0050. The router will
  match `matches_cwe` against the raw `Finding.Category` field for
  now; 0050 normalises Finding categories before the router sees
  them.
- **Health probing of external plugins** — feature 0051.
- **Per-plugin timeouts** — already in manifest as `timeout_s` but
  the proxy doesn't honour it yet. Out of scope.
- **Hot reload** — same as 0048.
- **Frontend changes** — none needed; `GET /api/agents` shape stays
  the same. (The optional follow-up is to surface plugin source
  ("in-tree" vs "external") in the agent selector, but that's a UI
  feature, not 0049.)

## Architecture

```
                       audit.Types (legacy)
                              ▼
                       ┌─────────────┐
                       │ AuditConfig │
                       └─────────────┘
                              │  + RequestContext (per stage)
                              ▼
                       ┌─────────────┐    ┌──────────────────┐
                       │ StageRouter ├───▶│ pluginregistry   │
                       └─────────────┘    └──────────────────┘
                              │                   │
                              ▼                   ▼
                       []DispatchTarget    Plugin manifests
                              │
                              ▼
                       ┌──────────────┐
                       │StreamService │  (dispatches to plugin URLs)
                       └──────────────┘
```

### Data shape

```go
// in backend/pkg/stagerouter/

// Stage indicates which pipeline phase is being routed.
type Stage string

const (
    StageScan     Stage = "scan"
    StageDiscover Stage = "discover"
    StageProve    Stage = "prove"
    StageValidate Stage = "validate"
)

// RouteRequest is everything the router needs to decide.
type RouteRequest struct {
    Stage      Stage
    // RequestedTypes carries the legacy AuditRequest.Types filter.
    // Empty means "no filter" — every matching plugin is dispatched.
    RequestedTypes []string
    // Languages observed in the source tree (populated by the
    // caller; the router doesn't sniff files).
    Languages  []string
    // TechStacks observed via Discover (populated by pipeline
    // service from prior stage output).
    TechStacks []string
    // PriorFindings supplied to Prove for CWE / check_id matching.
    PriorFindings []model.Finding
}

// DispatchTarget is one routing decision: a plugin to invoke.
type DispatchTarget struct {
    PluginName string
    URL        string  // resolved at route time
    Phase      string  // matches Capability.Phase
    Capability pluginregistry.Capability  // the matched capability
    // RequestedForFindings carries the subset of prior findings
    // that triggered this dispatch (prove only). Lets the proxy
    // pass only the relevant findings to each prove plugin.
    RequestedForFindings []model.Finding
}

// Router is the interface consumers see.
type Router interface {
    Route(req RouteRequest) ([]DispatchTarget, error)
}
```

### Routing logic, per stage

| Stage | Filter |
|---|---|
| `scan` | plugin has a `scan` capability AND (RequestedTypes empty OR plugin.name in RequestedTypes) AND (Capability.Languages empty OR overlap with RouteRequest.Languages) |
| `discover` | plugin has a `discover` capability AND (TechStacks empty OR Capability.TechStacks overlaps TechStacks) |
| `prove` | plugin has a `prove` capability AND at least one PriorFinding's CWE matches `matches_cwe` OR check_id matches `matches_check_id_prefix` |
| `validate` | plugin has a `validate` capability |

Each match produces one `DispatchTarget`. A plugin with multiple
capabilities for the same stage produces one target per matched
capability (caller can dedupe by `PluginName` if desired).

### URL resolution

```go
func (r *router) resolveURL(p pluginregistry.Plugin, agents map[string]config.AgentConfig) string {
    if a, ok := agents[p.Name()]; ok && a.URL != "" {
        return a.URL                       // legacy config.ini path
    }
    if envURL := os.Getenv("VULTURE_AGENT_" + strings.ToUpper(p.Name()) + "_URL"); envURL != "" {
        return envURL                      // operator override
    }
    if p.Manifest.Runtime.Type == pluginregistry.RuntimeContainer && p.Manifest.Runtime.Port > 0 {
        return fmt.Sprintf("http://agent-%s:%d", p.Name(), p.Manifest.Runtime.Port)
    }
    return ""                              // not reachable — caller skips
}
```

### Backwards compatibility

| Existing path | After 0049 |
|---|---|
| `service.streamService.StreamWithContext` iterates `audit.Types` | Replaced by `router.Route(StageScan, RouteRequest{RequestedTypes: audit.Types, ...})`. Same dispatch when no external plugins installed. |
| `pipeline_service.stageAuditTypes` returns `[]string` | Becomes `stageDispatchTargets` returning `[]DispatchTarget`. Internally calls the router. |
| `cfg.Agents[type]` lookup | Falls through `router.resolveURL`, which prefers `cfg.Agents`. |
| Prove agent receives ALL findings | After 0049: prove plugins receive only findings matching their `matches_cwe` / `matches_check_id_prefix`. **Behaviour change** — in-tree `prove` agent has no matches_cwe declared, so it gets EVERYTHING (preserving today's behaviour). |

The in-tree `prove` agent's virtual manifest (feature 0048) currently
emits zero `matches_cwe`. To preserve current behaviour we treat
"capability has no matches_cwe and no matches_check_id_prefix" as
"matches everything". This is documented in the router.

## Files touched

| File | Action |
|---|---|
| `docs/features/0049_stage_router/{plan,status,rollback}.md` | NEW (3 docs) |
| `backend/pkg/stagerouter/router.go` | NEW — Router interface, dispatcher |
| `backend/pkg/stagerouter/match.go` | NEW — per-stage match logic |
| `backend/pkg/stagerouter/url.go` | NEW — URL resolver |
| `backend/pkg/stagerouter/*_test.go` | NEW |
| `backend/internal/service/stream_service.go` | refactor to call router (feature-flag gated) |
| `backend/internal/service/pipeline_service.go` | **deferred** to follow-up — pipeline still uses `config.ScanAgentTypes()` for the in-tree default scan set; external plugins are dispatchable via the stream service when named in `audit.Types`. Full pipeline-level capability dispatch is in scope of 0050+ (CWE normalisation needs to land first for prove-stage routing to be useful). |
| `backend/internal/handler/stream_handler.go` | thread router through |
| `backend/internal/server/server.go` | wire `stagerouter.New(registry)` into service constructors |
| `backend/pkg/pluginregistry/virtual.go` | minor — set `tech_stacks` to `nil` (already nil, but document the "no filter" semantic in virtual manifests) |

Estimated LoC: ~500 net (300 new in stagerouter, ~200 modified in service layer).

## Acceptance criteria

1. **No-regression**: running an audit against a clean install with
   no external plugins produces identical SSE output and identical
   findings list as before 0049.
2. **Scan filter by language**: a synthetic test plugin declaring
   `languages = ["python"]` is only dispatched when the source has
   `.py` files. (Language detection is supplied via `RouteRequest.Languages`;
   the caller still sniffs files — that's not router work.)
3. **Discover filter by tech_stacks**: a wordpress discover plugin is
   dispatched only when `RouteRequest.TechStacks` contains `wordpress`.
4. **Prove filter by CWE**: a prove plugin with `matches_cwe = ["CWE-89"]`
   is dispatched only when at least one prior finding's category
   resolves to `CWE-89`. (Resolution is exact-match today; 0050
   adds the normalisation layer.)
5. **External plugin URL**: a manifest with `runtime.type=container, port=28100`
   produces a `DispatchTarget` whose URL is `http://agent-<name>:28100`
   (or honors `VULTURE_AGENT_<NAME>_URL`).
6. **Disabled plugin not dispatched**: a plugin with
   `state.toml: enabled=false` never appears in `Route()` output.
7. **Empty results don't crash**: routing with zero matches returns
   `[]DispatchTarget{}` and a nil error. Stream service handles the
   empty case by emitting `run_started` + `run_finished` without
   any agent goroutines.
8. **E2E**: a synthetic external plugin (HTTP echo server) is
   dispatched and its `finding` events propagate through SSE to the
   audit findings table.

## Implementation order (TDD)

1. Write failing E2E test for empty-routing case (no plugins installed
   except disabled in-tree ones).
2. Plan + status + rollback docs.
3. `stagerouter/router.go` types + `Route()` skeleton returning empty.
4. `stagerouter/match.go` — per-stage match logic with unit tests for
   each rule.
5. `stagerouter/url.go` — URL resolution with unit tests.
6. Wire into `service.streamService` behind a feature flag
   (`VULTURE_STAGE_ROUTER=true`) so we can run side-by-side until
   parity is confirmed.
7. Refactor `pipeline_service.stageAuditTypes` to delegate.
8. Remove the feature flag once all unit + E2E tests pass.
9. Add an E2E that launches a synthetic Python echo plugin and
   verifies its findings reach SSE.

## Security hardening

- **SH1**: `router.resolveURL` accepts URLs from manifests + env
  vars. Plugin manifests should NOT be able to override the legacy
  `cfg.Agents` URL (which is operator-controlled via config.ini).
  The order is: cfg.Agents → env override → manifest-derived URL.
  Manifest-derived URLs are inside the docker network only (the
  `agent-<name>` hostname is a docker-compose service alias).
- **SH2**: prove dispatch passes only the matching findings to each
  plugin (data minimisation). Prevents a third-party prove plugin
  from siphoning the entire findings corpus.
- **SH3**: the router never executes code from the manifest. It
  reads strings (CWE codes, language names, URL paths) only.
- **SH4**: `RequestedTypes` is treated as an allow-list, not a
  pattern — exact string match. Prevents glob/regex abuse from a
  malicious AuditRequest body.

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| Per-plugin findings dispatch breaks the in-tree prove agent | The "empty matches_cwe AND empty matches_check_id_prefix → matches all" rule preserves today's behaviour. Confirmed via the virtual manifest having both fields nil. |
| New dispatch path produces subtly different results | Feature-flag the rollout. Run side-by-side; remove flag once parity proven across multiple audits. |
| External plugin URLs not reachable in production | Document the URL-resolution order in the deployment guide; fall back to logging "[router] no URL for plugin X" and skipping. |
| Router becomes the bottleneck | It's pure CPU + map lookups. Plugins per registry ≤ 50 in any realistic install. |
