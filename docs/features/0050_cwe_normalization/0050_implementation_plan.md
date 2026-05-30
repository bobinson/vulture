# 0050 — CWE Normalisation Engine (LLD + plan)

**Author**: tbd
**Status**: PLAN — LLD reviewed (14 findings, 5 BLOCKERs), all incorporated below
**Created**: 2026-05-28
**Depends on**: 0047 (plugin contract), 0048 (registry), 0049 (stage router)
**Unblocks**: 0053 (Semgrep plugin) — without 0050, Semgrep findings won't route to CWE-specific prove plugins. Also enables cross-audit memory search by CWE.

## Reviewer-fix changelog (applied in this revision)

| # | Severity | Finding | Resolution in this LLD |
|---|---|---|---|
| 1 | BLOCKER | system map keys mismatch real agent output | seed data section rewritten from actual emitted strings (audited via grep) |
| 2 | BLOCKER | plugin-controlled AgentType breaks per-plugin scoping | `stream_handler.go` lines 420-421 + 789-790 hardened to unconditionally overwrite (in scope of 0050 wiring) |
| 3 | BLOCKER | canonical short-circuit suppresses plugin overrides | resolution order moves short-circuit to step 3, after plugin rules |
| 4 | BLOCKER | `Plugin.Name() == AgentInfo.Type` not enforced | new invariant test in `pluginregistry` for in-tree manifests |
| 5 | BLOCKER | DoS via unbounded per-plugin map entries | cardinality cap (10K per map) added to 0048 ValidateManifest |
| 6 | MAJOR | system CheckID prefix should beat system Category | resolution order: CheckID prefix tried before Category at system level |
| 7 | MAJOR | longest-prefix algorithm unspecified | linear scan with longest-match accumulator (pinned) |
| 8 | MAJOR | `NewWithLayer` API coherence | router struct has `layer cwe.Layer`; all constructors set it (nil → no-op pass-through) |
| 9 | MAJOR | RED tests blocked by un-pinned signatures | `matchPriorFindings` gains explicit 3rd parameter `layer cwe.Layer` |
| 10 | MAJOR | no operator override for embedded JSON | `VULTURE_CWE_SYSTEM_MAP_DIR` env var loads override JSONs |
| 11 | MAJOR | cross-language category-string drift | contract test in `layer_test.go` hard-codes every in-tree emitted category |
| 12 | MINOR | regex duplication justification inverted | justification corrected: cycle would be `internal/cwe → pluginregistry`, not the reverse |
| 13 | MAJOR | AC-8 not falsifiable | replaced with deterministic in-test prove plugin matching test |
| 14 | NIT | `FallbackCrossMap` undocumented | added to non-goals |

## Problem

The stage router introduced in 0049 routes prove-stage findings by
matching `Finding.Category` against `Capability.MatchesCWE`. Today
that's exact-string. Reality: finding categories vary by source:

| Agent | Typical `Category` value | Typical `CheckID` |
|---|---|---|
| cwe (in-tree) | `CWE-89` | `cwe.sql_injection_taint` |
| owasp (in-tree) | `A03-injection` | `owasp.injection.sql.parameterized_missing` |
| xss (in-tree) | `xss-reflected` | (often empty) |
| asvs | `ASVS-V5.3.4` | `asvs.v5_3_4` |
| semgrep (external) | rule-family string, e.g. `injection.sql` | rule id like `python.django.security.sql-injection` |

A prove plugin declaring `matches_cwe = ["CWE-89"]` only sees findings
whose `Category` is literally `"CWE-89"` — i.e., only cwe-agent
findings. Every other agent's SQLi findings are invisible to it.

0050 inserts a deterministic, plugin-aware **CWE normalisation layer**
that maps any finding to a canonical `CWE-NNN` (or empty if unknown)
without mutating the original `Category`. The router consults the
layer when matching prove plugins.

## Goal

Add `internal/cwe.Layer` — a read-only resolver that, given a
`(AgentType, Category, CheckID)` triple plus the plugin registry,
returns the canonical CWE string. Wire it into the stage router's
prove-matching path. Ship hand-curated baseline maps that cover
OWASP A1–A10, Semgrep's common security families, and the in-tree
non-CWE agents.

## Non-goals (deferred)

- **Persistence of normalised CWE in the database**. Compute-on-demand
  is sufficient for routing. Persisting the value (so memory-system
  semantic search can search by CWE) is a follow-up that requires a
  schema migration.
- **Multi-CWE per finding**. v1 returns a single CWE. Findings that
  legitimately map to several (misconfig family) get the most-specific
  one in the map.
- **Plugin-supplied `mapping_file` external files**. The
  `[normalization]` block already has a `mapping_file` field for
  pointing at plugin-shipped JSON; loading external files is a v1.1
  follow-up. v1 honours `rule_to_cwe` and `prefix_to_cwe` inline maps
  only.
- **`FallbackCrossMap` field** (parsed by 0048, present in
  `NormalizationBlock`). Semantics undefined in v1.0; 0050 ignores
  the field. Reserved for a future feature that defines what
  "fallback cross-map" means in operational terms.
- **Hot reload**. Layer is built once at startup; changes to manifest
  mappings or system data require a restart, consistent with 0048
  registry semantics.
- **Frontend display of normalised CWE**. UI continues to render
  `Category` only; UI work is a separate cosmetic task.
- **Backfill of historical findings**. Existing rows keep their
  pre-0050 routing semantics.

## Design

### Public API

```go
// in backend/internal/cwe/

package cwe

// Layer resolves a finding to a canonical CWE string. Empty result
// means "no mapping known"; callers treat that as "don't match
// CWE-filtered prove plugins".
type Layer interface {
    Normalize(agentType, category, checkID string) string
}

// New builds the default Layer from:
//   - embedded baseline maps (system/data/*.json)
//   - per-plugin maps from the supplied registry
// The layer is immutable after construction; safe for concurrent use.
func New(registry pluginregistry.Registry) Layer

// NewFromMaps constructs a layer directly from caller-supplied maps;
// used by tests to avoid touching embedded JSON or a real registry.
func NewFromMaps(
    perPluginRuleToCWE      map[string]map[string]string,
    perPluginPrefixToCWE    map[string]map[string]string,
    systemCategoryToCWE     map[string]string,
    systemCheckIDPrefixCWE  map[string]string,
) Layer
```

### Resolution order (deterministic, documented)

Per the reviewer (BLOCKERs 3, 6 + MAJORs 7): per-plugin rules ALWAYS
beat system base, even for findings whose `Category` is already
canonical. The canonical short-circuit fires only AFTER plugin rules
fail. At the system level, the more-specific `check_id_prefix`
match beats the coarser `category` map.

For a finding with `(AgentType, Category, CheckID)`:

1. **Plugin's `rule_to_cwe[CheckID]`** — exact match against the
   plugin keyed by `AgentType`. Per-plugin maps are scoped to one
   plugin only.
2. **Plugin's `prefix_to_cwe`** — longest-prefix match against
   `CheckID` (algorithm: linear scan of the map, accumulating the
   key with the longest matching length; deterministic regardless
   of map-iteration order).
3. **Canonical short-circuit** — if `Category` matches
   `^CWE-\d{1,5}$`, return as-is. This is the cheap path for
   cwe-agent findings that plugins didn't try to refine.
4. **Composite canonical** — if `Category` matches a `|`-separated
   list of canonical CWE IDs (e.g.
   `"CWE-79|CWE-113|CWE-644|CWE-1336"` from the xss-agent), return
   the first one. Documented carry-over for the legacy multi-CWE
   emission style.
5. **System `check_id_prefix_to_cwe`** — longest-prefix match
   (same algorithm as step 2).
6. **System `category_to_cwe[Category]`** — exact match.
7. **Empty string** — no mapping found; callers treat as "don't
   match CWE-filtered prove plugins."

Specificity rules: per-plugin beats system; CheckID prefix beats
Category at the system level.

### Integration with stage router (0049)

Per MAJORs 8, 9: the `router` struct gains a `layer cwe.Layer`
field. ALL existing constructors (`New`, `NewWithResolver`) set it
to a singleton no-op `passthroughLayer` whose `Normalize` returns
the empty string (so the legacy `cweMatches` path is used). One new
constructor pins the layer:

```go
// existing — preserved verbatim
func New(registry pluginregistry.Registry, agents map[string]config.AgentConfig) Router
func NewWithResolver(registry pluginregistry.Registry, resolver URLResolver) Router

// NEW — pins the layer
func NewWithLayer(registry pluginregistry.Registry,
                  agents map[string]config.AgentConfig,
                  layer cwe.Layer) Router
```

Internally, `New` and `NewWithResolver` set `r.layer = passthroughLayer{}`
explicitly. `NewWithLayer` calls into the same construction path
and overrides the layer.

`matchPriorFindings` gains an explicit third parameter:

```go
// before
func matchPriorFindings(c *Capability, findings []PriorFinding) []PriorFinding

// after
func matchPriorFindings(c *Capability, findings []PriorFinding, layer cwe.Layer) []PriorFinding
```

The caller (router.Route) passes `r.layer`. Inside, before the
existing `cweMatches` call, the matcher computes the effective CWE:

```go
effectiveCWE := layer.Normalize(f.AgentType, f.Category, f.CheckID)
if effectiveCWE == "" {
    effectiveCWE = f.Category    // fallback: legacy exact-string
}
if cweMatches(c.MatchesCWE, effectiveCWE) || checkIDMatches(...) {
    matched = append(matched, f)
}
```

A router built with `passthroughLayer` produces `effectiveCWE = f.Category`
on every call — bit-identical behaviour to 0049.

### AgentType invariant (BLOCKERs 2, 4)

The layer's per-plugin scoping correctness depends on
`Finding.AgentType == Plugin.Name()`. Three guarantees, enforced in
this revision:

1. **Proxy overwrite (BLOCKER 2)** — `stream_handler.go` lines
   ~420-421 and ~789-790, currently `if f.AgentType == "" { f.AgentType
   = agentType }`, are changed to unconditional `f.AgentType =
   agentType`. A container plugin can no longer spoof another
   plugin's identity in its SSE payload.

2. **In-tree synthesis invariant (BLOCKER 4)** — new test in
   `pkg/pluginregistry/virtual_test.go` asserts
   `Plugin.Name() == agentregistry.AllAgents[i].Type` for every
   virtual manifest. Caught at CI before any layer wiring runs.

3. **0050 graceful degradation** — if `f.AgentType == ""` (bug
   escapes the above), per-plugin maps simply don't apply; system
   maps still resolve. The layer never panics on empty input.

### Per-plugin map cardinality cap (BLOCKER 5)

`pluginregistry.ValidateManifest` gains a check rejecting any
`[normalization].rule_to_cwe` or `[normalization].prefix_to_cwe`
with more than `maxNormalisationEntries = 10000` entries. The cap
is a const in `pluginregistry/manifest.go`. A malicious manifest
shipping 10M entries fails registration before the layer ever sees
it.

### System baseline data (derived from actual in-tree agent output)

BLOCKER #1 fix: these JSON values are derived from `grep` against
`agents/*/*_agent/skills/` looking for emitted `"category"` and
`"check_id"` strings. Every key below has been confirmed against
live agent output.

`backend/internal/cwe/data/category_to_cwe.json`:

```json
{
  "A01-access-control":        "CWE-284",
  "A02-crypto-failure":        "CWE-310",
  "A03-injection":             "CWE-89",
  "A04-insecure-design":       "CWE-657",
  "A05-security-misconfig":    "CWE-16",
  "A06-vulnerable-components": "CWE-1104",
  "A07-auth-failure":          "CWE-287",
  "A08-data-integrity":        "CWE-345",
  "A09-logging-failure":       "CWE-778",
  "A10-ssrf":                  "CWE-918",

  "PO-prepare-organization":         "CWE-1053",
  "PS-protect-software":             "CWE-1357",
  "PW-produce-well-secured-software":"CWE-1059",
  "RV-respond-to-vulnerabilities":   "CWE-1053"
}
```

`backend/internal/cwe/data/check_id_prefix_to_cwe.json`:

```json
{
  "owasp.injection.sql":               "CWE-89",
  "owasp.injection.command":           "CWE-78",
  "owasp.access_control.":              "CWE-284",
  "owasp.auth.":                        "CWE-287",
  "owasp.crypto.":                      "CWE-310",
  "owasp.misconfig.":                   "CWE-16",
  "owasp.ssrf.":                        "CWE-918",
  "owasp.integrity.":                   "CWE-345",
  "owasp.logging.":                     "CWE-778",
  "owasp.vulnerable_components.":       "CWE-1104",
  "owasp.insecure_design.":             "CWE-657",
  "ssdf.po":                            "CWE-1053",
  "ssdf.pw":                            "CWE-1059",
  "ssdf.ps":                            "CWE-1357",
  "ssdf.rv":                            "CWE-1053"
}
```

Lists will grow; treat as data, not contract.

Files are loaded via `//go:embed` so the binary is self-contained.
Malformed JSON at build time fails the `go build`.

### Operator override (MAJOR #10)

`VULTURE_CWE_SYSTEM_MAP_DIR`, when set, points to a directory
containing override JSON files with the same names as the embedded
ones (`category_to_cwe.json`, `check_id_prefix_to_cwe.json`). Both
files are optional; missing or unreadable files fall through to
the embedded defaults. Keys present in the override files take
precedence (last-write-wins merge). This lets operators patch a
deployed binary without rebuilding.

### Per-plugin manifest maps

The plugin manifest's `[normalization]` block (already parsed in 0048,
unused until now) supplies:

```toml
[normalization]
[normalization.rule_to_cwe]
"semgrep.python.django.sql-1" = "CWE-89"

[normalization.prefix_to_cwe]
"semgrep.python.django." = "CWE-89"
```

0048's `ValidateManifest` already enforces `^CWE-\d{1,5}$` on values.
0050 reads these per-plugin and stores them keyed by `plugin.Name()`.

### Concurrency

Layer is built once and never mutated. Map reads are safe for
concurrent calls. No sync primitives needed.

## Threat model

### Path traversal via `mapping_file`

Schema accepts a `mapping_file` string in `[normalization]`. v1 of
0050 **does not load this** — we explicitly defer external file
loading. The field is parsed-and-ignored. If a future v1.1 loads
it, it must enforce the file resolves inside the plugin's own
directory (similar to 0050 SH4 below).

### Mapping injection

A user-supplied plugin shipping `rule_to_cwe = {"some.rule": "CWE-89"}`
will *only* affect findings emitted by **that** plugin (per-plugin
scope). Cannot pollute other plugins' findings.

### Resource exhaustion

Per-plugin maps are bounded by manifest size; the manifest itself is
size-validated in 0048 (string length caps). System maps are
embedded constants. No unbounded growth.

### Map shadowing

Per-plugin maps beat system base — but only for findings emitted by
that plugin. A community-signed plugin can't shadow the OWASP→CWE
mapping for OWASP-agent findings; only for its own.

## Reliability + chaos engineering

| Failure mode | Behaviour |
|---|---|
| Embedded JSON corrupt | Build fails (caught at compile time, never deploys) |
| `New(nil)` (no registry) | Returns a system-only layer; safe |
| Plugin manifest has no `[normalization]` | Per-plugin maps are empty; system maps still apply |
| Finding has empty `Category` and empty `CheckID` | Returns empty; router falls through to "no match" |
| Finding category is whitespace / nonsense | No match; returns empty |
| Router called without a layer | Behaviour identical to 0049 (exact-string match) |
| 100K findings normalised in a tight loop | Each call is 2–3 map lookups + a regex; ~200ns/finding → 20ms for 100K. Not a hot path. |
| Concurrent calls from N stream-service goroutines | Safe; maps are read-only |

## Maintenance

System mapping files are pure data. Updates flow:
1. Edit JSON in `internal/cwe/data/`.
2. Run `go test ./internal/cwe/` to validate values + schema.
3. Commit + rebuild.

Per-plugin maps live in plugin.toml under the plugin's own ownership;
operators edit, restart, done.

## DRY review

Where could 0050 logic duplicate existing code?

- `cwe_agent` (Python) does CWE detection — but it emits the canonical
  string directly. No need to duplicate detection in Go; we just
  pass-through the canonical form.
- `pluginregistry` already parses `[normalization]` blocks. 0050
  consumes that; doesn't re-parse.
- `stagerouter.match.go::cweMatches` is exact-string match. 0050
  doesn't duplicate it — it normalises BEFORE the existing match
  function runs.
- The schema regex `^CWE-\d{1,5}$` is duplicated in `pluginregistry`
  and would be in `internal/cwe`. MINOR #12 fix: the cycle direction
  is `internal/cwe → pluginregistry` (the layer imports the registry
  type for per-plugin maps); `pluginregistry` cannot import
  `internal/cwe` without a cycle. **Choice: keep both regexes; the
  duplication cost is two lines and changing the CWE format is a
  once-per-decade event.** A third zero-dependency package
  (`internal/cweformat`) is a viable future refactor if a third
  caller appears.
- **Cross-language drift (MAJOR #11)**: Python skill files
  (`agents/owasp/owasp_agent/skills/*.py`) embed the canonical
  category strings as literal `"category"` values. Go's system
  `category_to_cwe.json` keys mirror them. Drift would silently
  break normalisation. Mitigation: `layer_test.go` ships a
  contract test that hard-codes the in-tree category strings
  (from a grep against the skills) and asserts each resolves to
  a non-empty CWE. Drift fails CI.

## Files touched

| File | Action |
|---|---|
| `docs/features/0050_cwe_normalization/{plan,status,rollback}.md` | NEW |
| `backend/internal/cwe/layer.go` | NEW — types + New + impl |
| `backend/internal/cwe/embed.go` | NEW — `//go:embed` system data |
| `backend/internal/cwe/data/category_to_cwe.json` | NEW |
| `backend/internal/cwe/data/check_id_prefix_to_cwe.json` | NEW |
| `backend/internal/cwe/layer_test.go` | NEW (RED phase) |
| `backend/pkg/stagerouter/router.go` | modified — accept optional Layer |
| `backend/pkg/stagerouter/match.go` | modified — normalise before matching |
| `backend/pkg/stagerouter/match_normalize_test.go` | NEW (RED phase) |
| `backend/internal/server/server.go` | modified — wire layer into router |

Estimated LoC: ~400 net.

## Acceptance criteria

1. **Plugin rule wins over canonical category** (BLOCKER #3 fix) —
   `Normalize("semgrep", "CWE-89", "rule-X")` where semgrep manifest
   maps `rule-X → CWE-564` returns `"CWE-564"`, NOT `"CWE-89"`.
2. **Plugin prefix wins over system base** — `Normalize("semgrep",
   "A03-injection", "semgrep.python.sql.injection")` returns the
   plugin's prefix mapping, not the system A03 mapping.
3. **Longest-prefix match (linear-scan accumulator)** — given map
   `{"python.": "CWE-693", "python.django.security.sql-injection":
   "CWE-89"}`, `Normalize` of a checkID `"python.django.security.sql-injection.unsafe-raw"`
   returns `"CWE-89"`, regardless of map iteration order. (MAJOR #7)
4. **System CheckID prefix beats system Category** (MAJOR #6) —
   `Normalize("owasp", "A03-injection", "owasp.injection.command")`
   returns `"CWE-78"`, NOT `"CWE-89"`.
5. **Canonical short-circuit (cheap path)** — `Normalize("cwe",
   "CWE-89", "")` returns `"CWE-89"` when no plugin map applies.
6. **Composite canonical** — `Normalize("xss",
   "CWE-79|CWE-113|CWE-644|CWE-1336", "")` returns `"CWE-79"` (first).
7. **No match → empty** — `Normalize("zz", "garbage", "garbage")`
   returns `""`.
8. **Real in-tree contract test (MAJOR #11)** —
   `Normalize("owasp", "A01-access-control", "")`,
   `Normalize("owasp", "A09-logging-failure", "")` etc. (full sweep
   of strings emitted by `agents/*/skills/*.py`) each return a
   non-empty CWE.
9. **Router prove-stage integration (replaces AC-8; MAJOR #13)** —
   With layer wired and a test plugin declaring `matches_cwe =
   ["CWE-284"]`, a prove-stage route call carrying a prior finding
   with `Category = "A01-access-control"`, `AgentType = "owasp"`
   matches and produces a `DispatchTarget` whose `MatchedFindings`
   contains the finding.
10. **No-regression without layer** — Router constructed via `New`
    (not `NewWithLayer`) produces dispatch identical to 0049 across
    every existing 0049 test.
11. **Operator override (MAJOR #10)** —
    `VULTURE_CWE_SYSTEM_MAP_DIR` pointing at a temp dir with a
    `category_to_cwe.json` containing
    `{"A03-injection": "CWE-9999"}` causes
    `Normalize("owasp", "A03-injection", "")` to return `"CWE-9999"`.
12. **Cardinality cap (BLOCKER #5)** — A manifest with `prefix_to_cwe`
    of 10001 entries is rejected by `ValidateManifest` with a
    cardinality error.
13. **AgentType proxy hardening (BLOCKER #2)** — When the agent's
    SSE payload includes `"agent_type": "spoof"` but the proxy
    dispatched to plugin `owasp`, the persisted `Finding.AgentType`
    is `"owasp"`, NOT `"spoof"`.
14. **Plugin.Name == AllAgents.Type invariant (BLOCKER #4)** — a
    new test in `pkg/pluginregistry/virtual_test.go` walks every
    in-tree virtual manifest and asserts the equality.

## Build sequence (TDD with RED → GREEN subagents)

1. **LLD doc** (this file).
2. **LLD review** — code-reviewer subagent reads this doc + the
   files it claims to touch; reports correctness, reliability,
   maintenance, chaos engineering, security, DRY findings.
3. **RED phase** — general-purpose subagent writes ONLY test files:
   - `internal/cwe/layer_test.go`
   - `pkg/stagerouter/match_normalize_test.go`
   No implementation. Tests must compile but fail.
4. **Verify failure** — `go test ./internal/cwe/ ./pkg/stagerouter/`
   confirms the new tests fail (other suites still pass).
5. **GREEN phase** — general-purpose subagent writes minimal
   implementation to pass the supplied tests, plus the embedded JSON
   data files. Modifies router/match minimally.
6. **Verify pass** — `go test -race ./...` clean across all
   packages.
7. **Wire into server.New**.
8. **E2E** — start vulture pointing at `backend/` source, trigger
   an audit, verify a non-CWE-prefixed finding (e.g., from owasp
   agent) has its CWE resolved by the layer.

## Rollback

The layer is a strict addition. Failure modes:

| Failure | Rollback |
|---|---|
| Layer produces wrong CWE for a class of findings | Patch the JSON map (no code change) |
| Layer panics under unexpected input | `defer recover` at the Normalize boundary, return empty |
| Router-layer integration breaks 0049 path | `server.New` passes `nil` layer → identical to 0049 |
| Full revert needed | `git revert <merge-sha>`; no DB migration to undo |

Forward-fix is almost always the right call; the layer is data-driven.
