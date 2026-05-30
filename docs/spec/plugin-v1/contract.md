# Vulture Plugin Contract — `vulture-plugin/1.0`

**Status**: stable
**Released**: 2026-05-25
**Maintainer**: Vulture core team
**Source of truth**: `docs/spec/plugin-v1/`

This document defines the contract every Vulture plugin honours. It is
the long-form complement to `manifest.schema.json` and the per-event
schemas under `events/`.

A "plugin" is a sidecar service (typically a container) that extends
Vulture's audit pipeline. Plugins can participate in any of four
phases: **scan**, **discover**, **prove**, and **validate**. The same
plugin process MAY serve multiple phases.

---

## Table of contents

1. [Goals](#goals)
2. [Non-goals](#non-goals)
3. [Architecture](#architecture)
4. [Manifest format](#manifest-format)
5. [API contract](#api-contract)
6. [Event shapes](#event-shapes)
7. [Phase semantics](#phase-semantics)
8. [Capability negotiation](#capability-negotiation)
9. [CWE normalisation](#cwe-normalisation)
10. [Trust tiers](#trust-tiers)
11. [Lifecycle](#lifecycle)
12. [Conformance](#conformance)
13. [Versioning](#versioning)
14. [Open questions](#open-questions)

---

## Goals

1. **One contract for every phase.** Scan, discover, prove, and
   validate plugins all implement the same three HTTP endpoints. The
   payload differs by `stage`; the envelope does not.
2. **Multi-language plugin authoring.** Any process that speaks HTTP
   and emits Server-Sent Events qualifies. Python, Ruby (for
   Metasploit), Java, Go, Rust, Node — all first-class.
3. **CWE normalisation is mandatory for scan plugins.** No more
   detector-specific category strings leaking into validate's L1
   sanitiser map or L3 cross-agent dedup.
4. **Default-enabled after install.** Once `vulture plugin install
   <name>` succeeds, the plugin participates in audits without further
   opt-in (subject to per-tier trust acknowledgements).
5. **RC3 isolation extends to plugins.** A crashing plugin reduces
   coverage; it never aborts an audit.

## Non-goals

- **Not a marketplace.** A curated JSON registry of community plugins
  is maintained by the Vulture team; submission is via pull request.
- **Not in-process Python.** Plugins are sidecars. This rules out
  `setuptools` entry-point style extension but unlocks every other
  language.
- **Not a sandbox.** Container isolation is the boundary. WASM-style
  capability sandboxing is out of scope.
- **Not a workflow engine.** Plugins emit events; the orchestrator
  routes. Plugins cannot consume each other's output directly.

## Architecture

```
                       Vulture backend (orchestrator)
                                    │
                                    │ HTTP + SSE
        ┌──────────────┬────────────┼────────────┬──────────────┐
        ▼              ▼            ▼            ▼              ▼
   in-tree agent  community plugin  user-supplied plugin  ...   ...
   (chaos, cwe,   (semgrep, gosec,  (metasploit, zap,
    owasp, ...)    spotbugs, ...)    custom-internal, ...)
```

Each plugin runs as its own service (container, host binary, or
in-tree module). The orchestrator addresses it by URL.

## Manifest format

Every plugin ships a `plugin.toml` at its root (or in the container at
a known path). The orchestrator loads this manifest at install time
and re-reads on `vulture plugin reload`.

Full schema: `manifest.schema.json`. Required fields and shape:

```toml
# ── Identity (REQUIRED) ──────────────────────────────────────────────
[plugin]
name           = "semgrep"                 # unique slug, [a-z0-9_-]+
display_name   = "Semgrep"                 # human-readable
version        = "1.0.0"                   # semver
api_version    = "vulture-plugin/1.0"      # contract version this plugin honours
publisher      = "returntocorp"
description    = "Cross-language SAST via the Semgrep engine."

# Optional metadata
homepage       = "https://semgrep.dev"
license        = "LGPL-2.1"
documentation  = "https://semgrep.dev/docs"

# ── Trust (REQUIRED) ─────────────────────────────────────────────────
[trust]
tier           = "community-signed"   # in-tree | community-signed | user-supplied

# Required for community-signed: cosign keyless OIDC identity reference
signature      = "cosign://sigstore/returntocorp/semgrep-plugin"

# Required for user-supplied tier: list of acknowledgements the
# operator must pass to `vulture plugin install --trust <ack1,ack2>`.
# Enum (see "Trust tiers" section).
required_ack   = []

# ── Runtime (REQUIRED) ───────────────────────────────────────────────
[runtime]
type           = "container"          # container | host-binary | in-tree
image          = "returntocorp/vulture-semgrep:1.0.0"
port           = 8080
health_endpoint = "/health"
info_endpoint  = "/info"
run_endpoint   = "/run"
restart        = "unless-stopped"
network        = "internal"           # internal | host | none
resources      = { cpu = "2", memory = "4Gi" }

# Filesystem access (declared at install, enforced by orchestrator):
[runtime.fs]
read           = ["/src"]             # default: read-only source mount
write          = ["/tmp/plugin-work"] # default: a sandbox tmp dir

# Environment variables the plugin needs from the orchestrator:
[runtime.env]
required       = ["VULTURE_LLM_MODEL"]     # forwarded if set in operator env
optional       = ["OPENAI_API_KEY"]

# ── Capabilities (REQUIRED — at least one block) ────────────────────
[[capabilities]]
phase          = "scan"               # scan | discover | prove | validate
languages      = ["javascript", "typescript", "python", "go", "java"]
emits          = ["finding"]
timeout_s      = 600
selectors      = {}                   # scan plugins typically run on whole source

# A plugin can serve multiple phases — add more [[capabilities]] blocks:
[[capabilities]]
phase          = "validate"
emits          = ["validation_update"]
timeout_s      = 60

# ── CWE normalisation (REQUIRED for scan phase) ────────────────────
[normalization]
# Option 1: inline table (for small mappings)
[normalization.rule_to_cwe]
"javascript.express.security.express-sql-injection" = "CWE-89"

# Option 2: prefix match (catches whole rule families)
[normalization.prefix_to_cwe]
"javascript.lang.security.audit.xss."   = "CWE-79"
"python.lang.security.audit.dangerous." = "CWE-78"

# Option 3: external file shipped inside the container
# mapping_file = "/etc/vulture-plugin/rules-to-cwe.json"

# Option 4: orchestrator-provided fallback
fallback_cross_map = "owasp_top_10_2021_to_cwe"
```

### Required fields by phase

| Phase    | `[normalization]` required? | `emits` must include |
|----------|-----------------------------|----------------------|
| scan     | **yes**                     | `finding`            |
| discover | no                          | `discover_result`    |
| prove    | no                          | `proof_phase`, `proof_attempt`, `proof_result` (any subset) |
| validate | no                          | `validation_update`  |

### Field constraints

| Field                    | Constraint                                                    |
|--------------------------|---------------------------------------------------------------|
| `plugin.name`            | `^[a-z][a-z0-9_-]{1,63}$` — unique within installation        |
| `plugin.version`         | Semver 2.0.0                                                  |
| `plugin.api_version`     | Exact string `vulture-plugin/<major>.<minor>` — currently `vulture-plugin/1.0` |
| `trust.tier`             | One of `in-tree`, `community-signed`, `user-supplied`         |
| `trust.required_ack`     | Subset of `runs-real-exploits`, `network-egress`, `host-fs-write`, `privileged` |
| `runtime.type`           | One of `container`, `host-binary`, `in-tree`                  |
| `runtime.port`           | 1024-65535 (when type=container or host-binary)               |
| `capabilities[].phase`   | One of `scan`, `discover`, `prove`, `validate`                |
| `capabilities[].emits[]` | Each must be a valid AG-UI event name (see "Event shapes")    |
| `capabilities[].languages[]` | Canonical lowercase: `python`, `javascript`, `typescript`, `go`, `java`, `kotlin`, `rust`, `ruby`, `csharp`, `php`, `cpp`, `c`, `swift`, `scala`, `shell`, `sql`, `yaml`, `json`, `dockerfile`, `unknown` |
| `normalization.rule_to_cwe[].<value>` | `^CWE-\d{1,5}$`                                |
| `normalization.prefix_to_cwe[].<value>` | `^CWE-\d{1,5}$`                              |

## API contract

Three endpoints, all served from the same plugin process.

### `GET /info` — capability + readiness self-description

Returns the plugin's runtime-resolved state. The orchestrator polls
this at install + on each `vulture plugin reload`.

```json
{
  "envelope": "vulture-plugin/1.0",
  "name": "semgrep",
  "version": "1.0.0",
  "phases": ["scan"],
  "capabilities": [
    {
      "phase": "scan",
      "languages": ["javascript", "typescript", "go", "java"],
      "emits": ["finding"]
    }
  ],
  "tool_versions": { "semgrep": "1.45.0" },
  "ruleset_versions": { "p/javascript": "2026.04.15" },
  "status": "ready"
}
```

### `GET /health` — liveness probe

Returns 200 + `{"status": "ok" | "degraded" | "down", "details": "..."}`.

`degraded` means "still serving requests, but at reduced quality" (e.g.
ruleset out of date). The orchestrator continues to dispatch.

`down` means "do not dispatch". The orchestrator will retry the health
probe with exponential backoff.

### `POST /run` — phase-agnostic invocation

Request envelope:

```json
{
  "envelope": "vulture-plugin/1.0",
  "run_id": "<audit-id>",
  "stage": "scan",
  "input": { ... },        // stage-specific; see Phase semantics
  "config": {
    "timeout_s": 600,
    "max_iterations": 5,
    "compliance_mode": false
    // arbitrary additional config under operator/agent control
  },
  "trust_acks": []         // acknowledgements operator gave at install
}
```

Response: HTTP 200, `Content-Type: text/event-stream`, followed by an
SSE stream of AG-UI events terminated by `run_finished`. The first
event MUST be `run_started`; the last MUST be `run_finished`.

If the plugin cannot serve the request at all (e.g. tool not
installed), it MUST return 200 + an SSE stream containing a single
`thinking` event with a diagnostic message, then `run_finished` with
`status="degraded"`. It MUST NOT return a 5xx — that would cause the
orchestrator to retry.

Errors during a run are reported in-band via `thinking` events. The
plugin SHOULD set `run_finished.status="failed"` if no useful output
was produced.

## Event shapes

All events match the AG-UI envelope already used by in-tree agents.
Per-event JSON schemas for **the five load-bearing events** live in
`docs/spec/plugin-v1/events/`:

- `finding.schema.json`
- `discover_result.schema.json`
- `proof_result.schema.json`
- `validation_update.schema.json`
- `run_finished.schema.json`

The remaining events (`run_started`, `agent_start`, `agent_end`,
`thinking`, `progress`, `proof_phase`, `proof_plan`, `proof_review`,
`proof_attempt`, `proof_reflection`, `proof_summary`, `dedup_stats`,
`token_savings`, `result`) inherit the existing AG-UI agent contract
without per-event schemas in v1.0 — their shape is stable in the
in-tree implementation and re-documenting them here would just
duplicate `backend/internal/agui/translator.go`. A v1.1 spec bump may
ship additional schemas as plugin authors hit ambiguities.

The canonical event set:

| Event                | Emitted by phases     | Purpose                                  |
|----------------------|-----------------------|------------------------------------------|
| `run_started`        | all                   | First event; declares run + thread IDs   |
| `agent_start`        | all                   | Optional; legacy compatibility           |
| `agent_end`          | all                   | Optional; legacy compatibility (pair with `agent_start`) |
| `thinking`           | all                   | Free-form log line (UTF-8, ≤ 4 KB)        |
| `progress`           | scan, discover        | `{files_analyzed, total_files, findings_count}` |
| `finding`            | **scan**              | One emitted finding (see Finding schema) |
| `discover_result`    | **discover**          | Site map / endpoint inventory            |
| `proof_phase`        | **prove**             | Phase marker (e.g. "selecting module")    |
| `proof_plan`         | **prove**             | Verification plan text                   |
| `proof_review`       | **prove**             | Safety review of the plan                |
| `proof_attempt`      | **prove**             | One probe iteration's evidence           |
| `proof_reflection`   | **prove**             | Self-learning analysis (optional)        |
| `proof_result`       | **prove**             | Final per-finding verdict                |
| `proof_summary`      | **prove**             | Per-run aggregate                        |
| `validation_update`  | **validate**          | `{updates: [{id, validation_status, validation_confidence, validation}]}` |
| `dedup_stats`        | scan (optional)       | Plugin reports cross-audit dedup metrics |
| `token_savings`      | scan (optional)       | LLM-using plugins report budget          |
| `result`             | all (optional)        | Aggregate per-run summary                |
| `run_finished`       | all                   | Terminal event; `status: completed | failed | degraded` |

### `finding` schema (required for scan plugins)

```json
{
  "id": "<plugin-supplied stable id; optional — orchestrator hashes if absent>",
  "severity": "critical | high | medium | low | info",
  "category": "CWE-89",          // MUST be CWE-prefixed after normalisation
  "title": "SQL injection in /api/users",
  "description": "...",
  "file_path": "/src/api/users.js",
  "line_start": 42,
  "line_end": 47,
  "check_id": "semgrep.javascript.express.security.express-sql-injection",
  "code_snippet": "...",
  "recommendation": "...",
  "references": ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

Required fields: `severity`, `category`, `title`, `description`,
`file_path`, `line_start`. Everything else is optional but encouraged.

### `validation_update` schema (validate plugins)

```json
{
  "phase": "<plugin-name>",
  "updates": [
    {
      "id": "<finding-id>",
      "validation_status": "high_confidence | suspicious | likely_fp",
      "validation_confidence": 0.0..1.0,
      "validation": {
        "checks": [
          {
            "id": "<plugin-name>",
            "result": "real_bug | demoted | error | neutral",
            "weight": -0.75..+0.75,
            "reason": "...",
            "extras": { ... }
          }
        ]
      }
    }
  ]
}
```

Validate plugins MUST NOT use a `check.id` of any value reserved by
in-tree layers (`path`, `suppression`, `sanitizer`, `rollup`,
`cross_agent`, `memory`, `llm_judge`). The plugin's `name` is the
recommended `check.id`.

## Phase semantics

### Scan

**Input** (`POST /run` body, `input` field):

```json
{
  "source_path": "/src",
  "files_changed": ["api/users.js"]   // optional incremental hint
}
```

**Plugin contract**:
- MAY scan all files in `source_path` or limit to `files_changed`.
- MUST emit `finding` events for each detection.
- MUST emit each finding with a CWE-prefixed `category` after applying
  its `[normalization]` rules.
- SHOULD emit `progress` events for long scans.
- SHOULD respect `config.timeout_s`.

**Orchestrator behaviour**:
- Dispatches ALL enabled scan plugins whose `capabilities[].languages`
  include at least one language from the source set (or whose
  `languages` is empty = any).
- Pipes findings through validate (L1-L5) — plugins do not run their
  own validate logic unless they also have a `validate` capability.

### Discover

**Input**:

```json
{
  "target_url": "https://staging.example.com",
  "auth": { ... },             // optional
  "max_depth": 3,
  "max_iterations": 50
}
```

**Plugin contract**:
- Emits `discover_result` events to extend the site map.
- May emit multiple `discover_result` events; orchestrator merges.

**Orchestrator behaviour**:
- Dispatches ALL enabled discover plugins whose
  `capabilities[].tech_stacks` matches or is empty.
- Aggregates URL / endpoint / form inventories.

### Prove

**Input**:

```json
{
  "finding": { "id": ..., "category": "CWE-89", "file_path": ..., ... },
  "target": {
    "staging_url": "https://staging.example.com",
    "allow_local": false,
    "credentials": { ... }
  }
}
```

**Plugin contract**:
- Emits `proof_phase` → `proof_plan` → `proof_attempt`(*) →
  `proof_result` in order.
- MUST respect `config.max_iterations`.
- MUST NOT make calls outside `target.staging_url`'s origin without
  the operator's explicit `network-egress` ack.
- `proof_result.status ∈ {verified, not_reproduced, inconclusive, skipped}`.

**Orchestrator behaviour**:
- For each finding, lists prove plugins matching the finding's
  `category` (via `matches_cwe`) or `check_id` (via
  `matches_check_id_prefix`).
- Runs matched plugins in parallel (subject to per-tier concurrency
  caps). Verdicts are merged: if ANY plugin reports `verified`, the
  finding is `verified`. Otherwise the highest-confidence verdict
  wins.

### Validate

**Input**:

```json
{
  "findings": [ { ... }, { ... } ],   // post-L1-L5
  "audit_id": "...",
  "compliance_mode": false
}
```

**Plugin contract**:
- Emits `validation_update` events with new check entries.
- MUST NOT mutate fields outside `validation.checks` and the rolled-up
  `validation_status` / `validation_confidence`.

**Orchestrator behaviour**:
- Chains after in-tree L1-L5. Per-plugin `validation_update` updates
  flow through the same voter.
- Multiple validate plugins run in declared order (typically install
  order); each sees the previous plugins' contributions.

## Capability negotiation

The orchestrator picks which plugins to dispatch by matching the
`input` against each plugin's `[[capabilities]]` blocks. Matching is
permissive: an empty selector field means "matches anything".

### Scan matching

A scan plugin runs if:
- `capabilities[i].phase == "scan"` AND
- (`capabilities[i].languages` is empty OR at least one language in
  the source set appears in `capabilities[i].languages`)

### Discover matching

A discover plugin runs if:
- `capabilities[i].phase == "discover"` AND
- (`capabilities[i].tech_stacks` is empty OR target's fingerprinted
  tech stack overlaps)

### Prove matching

A prove plugin runs per-finding if:
- `capabilities[i].phase == "prove"` AND
- ANY of:
  - `capabilities[i].matches_cwe` is empty, OR
  - finding's `category` is in `matches_cwe`, OR
  - finding's `check_id` matches a prefix in `matches_check_id_prefix`

### Validate matching

All enabled validate plugins run on every audit's findings.

### `selectors` (free-form extension point)

The `selectors` field on a capability block is a free-form object
the orchestrator passes verbatim to its matching code. Per phase:

| Phase | Recognised keys (v1.0) |
|---|---|
| scan | `file_patterns: [str]` — glob patterns the plugin scans (orchestrator filters source files). `max_file_size_kb: int` |
| discover | `tech_stack: [str]` — tags from a discovery fingerprint pass |
| prove | `severity_min: str` — only dispatch on findings of this severity or higher. `language: [str]` |
| validate | (none in v1.0) |

Unknown keys are silently ignored. Plugin authors can declare keys
the orchestrator doesn't know — they'll be available to user-defined
routing scripts in a future version but have no effect in v1.0.

## CWE normalisation

This is non-negotiable for scan plugins. Without it, validate's
cross-agent dedup, L1 sanitiser map, L2 rollup, L3 corroboration, and
L4 memory inheritance all break.

### Three layers

**Layer A — plugin-side mapping (REQUIRED for scan)**

The plugin's `[normalization]` block declares the rule-to-CWE mapping.
Three sub-modes (combine freely):

```toml
# Inline exact map — best for ≤ 100 rules
[normalization.rule_to_cwe]
"semgrep.javascript.express.express-sql-injection" = "CWE-89"

# Prefix map — best for rule families
[normalization.prefix_to_cwe]
"semgrep.javascript.lang.security.audit.xss." = "CWE-79"

# External file shipped in the plugin's container (for large maps)
mapping_file = "/etc/vulture-plugin/rules-to-cwe.json"
```

The orchestrator applies the mapping at ingest, in this order: exact
match → prefix match → external file → fallback cross-map → tag as
`_unnormalised`.

**Layer B — orchestrator fallback maps**

Vulture ships canonical cross-maps in
`agents/shared/shared/normalization/cwe_maps/`:

- `owasp_top_10_2021_to_cwe.json`
- `sans_top_25_to_cwe.json`
- `semgrep_rule_metadata_extracted.json` (auto-extracted from Semgrep
  community rules' metadata)
- `bandit_test_id_to_cwe.json`
- `gosec_rule_to_cwe.json`

A plugin can reference any of these as a fallback:

```toml
[normalization]
fallback_cross_map = "owasp_top_10_2021_to_cwe"
```

**Layer C — unnormalised escape hatch**

If no layer produces a CWE, the orchestrator emits the finding with:
- `category = "plugin:<plugin-name>/<original-rule-id>"`
- `_unnormalised = true`
- A warning logged: `"[plugin.<name>] cannot normalise rule <id> — surface to operator"`

The finding still flows through validate, but with degraded dedup
quality. Operators see the warning and can either:
- Edit the plugin's manifest to add the mapping locally, OR
- File an issue against the plugin's repo.

### Why this is mandatory

Without normalisation:

- Cross-agent dedup (L3) can't merge a Semgrep CWE-89 with an in-tree
  CWE skill's CWE-89 — different category strings, no merge.
- L1 sanitiser map is CWE-keyed — non-CWE categories skip
  language-aware sanitiser detection entirely.
- L2 rollup groups by `(category, file_path)` — different categories
  mean no rollup, so the same bug shows up N times in the UI.
- L4 memory_prior inheritance fingerprints include category — a user
  labelling a Semgrep verdict as FP doesn't propagate to CWE-skill
  findings of the same CWE.

## Trust tiers

Three tiers, with escalating opt-in friction:

### `in-tree`

Plugins shipped with Vulture itself. No install step — they're always
present. Examples: today's 10 agents.

- Manifest signature: not required (the repo signs the release).
- Default enablement: yes.
- `required_ack`: empty (the repo's own CI/CD is the trust boundary).

### `community-signed`

Plugins from third parties signed via Sigstore cosign keyless OIDC.

- Manifest signature: **required**. The `trust.signature` field gives
  the cosign identity URL. Orchestrator verifies on every install +
  on `vulture plugin verify`.
- Default enablement: yes (after install).
- `required_ack`: typically empty; allowed `runs-real-exploits` if the
  plugin includes scanner-mode exploit verification.
- Distribution: container images pushed to ghcr.io / docker hub +
  cosign signature stored alongside.

### `user-supplied`

Plugins the operator chose to install from outside the curated
registry: internal proprietary tools, niche scanners, offensive
frameworks.

- Manifest signature: optional.
- Default enablement: yes (after install with `--trust`).
- `required_ack`: **at least one** must be declared and the operator
  must pass it to `vulture plugin install --trust <ack1,ack2,...>`.

### Trust acknowledgement enum

Valid values for `trust.required_ack`. Each ack maps to a specific
capability the plugin needs that an operator should consciously
allow before install:

| Ack                  | Meaning                                                                | Typical orchestrator enforcement |
|----------------------|------------------------------------------------------------------------|----------------------------------|
| `runs-real-exploits` | Plugin sends real exploit payloads to the staging target               | UI warning per finding; logged per run |
| `network-egress`     | Plugin makes outbound network calls beyond the staging target          | `runtime.network = "host"` triggers this auto |
| `host-fs-write`      | Plugin writes to the host filesystem outside its sandbox tmp dir       | `runtime.fs.write` entries outside `/tmp/*` require this |
| `privileged`         | Plugin requires `--privileged` container or root host access           | Highest-friction ack; orchestrator may refuse to install on production deployments |
| `commercial-key`     | Plugin requires a paid commercial API key passed via `runtime.env`     | Operator confirms billing acceptance |
| `gpu-access`         | Plugin requires GPU device access                                      | `--gpus all` on docker run |
| `kernel-modules`     | Plugin requires loading kernel modules (e.g. eBPF-based scanners)      | Linux capabilities CAP_SYS_MODULE; rarely available in CI |

The orchestrator MUST persist the operator's `--trust` acknowledgement
in `state.toml:trust_acks` and refuse to dispatch if a required ack
is missing. Re-installing the plugin (e.g. version bump) preserves
existing acks if and only if the new manifest's `required_ack` set
is a subset of the recorded acks — otherwise the operator must
re-acknowledge.

Extensions to this list require a minor version bump on `api_version`
(`1.0` → `1.1`). Existing manifests with the older enum continue to
work; new acks need a new orchestrator.

## Lifecycle

```
DISCOVERED   (manifest seen at install)
   │
   ▼
INSTALLED    (state.toml entry written; cosign verified for community tier;
   │          acks recorded for user-supplied tier)
   │
   ▼
ENABLED      ← default after INSTALLED unless `--disabled` was passed
   │
   ▼
HEALTHY      (probed via GET /health)
   │
   ├──────────────────────────────────────────────────────► DEGRADED → re-probe
   │                                                             ↓
   ▼                                                          DISABLED (auto, after N failures)
DISPATCHED   (per audit, per matching capability)
   │
   ▼
EVENTS-EMITTED  (via SSE; orchestrator processes per-event)
   │
   ▼
RUN-FINISHED   (terminal event; orchestrator marks finding-emissions complete)
```

### State file

`~/.vulture/plugins/state.toml`:

```toml
[plugins.semgrep]
installed_at  = "2026-05-27T13:21:00Z"
version       = "1.0.0"
enabled       = true
trust_acks    = []
last_verified = "2026-05-27T13:21:00Z"
last_run      = "2026-05-27T14:55:42Z"
last_run_status = "completed"
emissions_30d_total = 4823     # for emission-cap enforcement
```

## Conformance

A plugin is conformant if and only if:

1. `plugin.toml` validates against `manifest.schema.json`.
2. Every event emitted matches its schema in `docs/spec/plugin-v1/events/`.
3. Every event emitted appears in some `capabilities[].emits` list.
4. For scan plugins: every emitted finding has `category` matching
   `^CWE-\d+$` after the orchestrator's normalisation step.
5. The plugin exits gracefully on `config.timeout_s` expiry — `SIGTERM`
   handled, last in-flight events flushed.
6. The plugin handles `POST /run` with an unknown `stage` by emitting
   a single `thinking` "unsupported stage" event and `run_finished:
   status=degraded`.

The `tools/plugin_lint/` CLI exercises checks 1, 3, and 4 statically.
Checks 2, 5, 6 require runtime probing (out of scope for v1.0
conformance — added in a future linter mode).

## Versioning

Semver applied to `api_version`:

- **Major bump** (1.0 → 2.0): incompatible change. Orchestrator that
  supports only `2.x` refuses to load `1.x` plugins.
- **Minor bump** (1.0 → 1.1): backward-compatible additions. New
  optional fields, new event types, new ack values. Existing plugins
  keep working.
- **Patch bump** (1.0.0 → 1.0.1): documentation clarification only.
  No schema changes.

The orchestrator declares its supported version range in
`AllAgents.api_version_min` / `api_version_max` (added in 0048).

### Deprecation policy

A field marked `deprecated_at: <date>` in the schema continues to be
accepted for at least 6 months. The orchestrator emits a warning at
install but does not refuse. After the deprecation period, the field
is removed in the next major version.

## Open questions

(non-blocking; tracked for future revision)

1. Should the contract include a metric / telemetry endpoint
   (`GET /metrics` in Prometheus format)? Currently optional.
2. Should plugins declare expected emission counts (`emissions_per_audit_estimate`)
   so the orchestrator can pre-allocate resources? Today: no.
3. Cross-plugin dependencies (Plugin A needs Plugin B installed):
   defer to v1.1 if real demand emerges.
4. Should `validation_update` events carry a confidence priority so
   plugin chains can short-circuit? Defer to v1.1.

---

## Changelog

| Version | Date       | Change                                  |
|---------|------------|-----------------------------------------|
| 1.0.0   | 2026-05-25 | Initial release                         |
