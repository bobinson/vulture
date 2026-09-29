# Vulture - Agent Protocol

## Overview

Vulture uses a two-layer protocol for agent communication:

1. **Go Backend ↔ Python Agents**: HTTP + SSE (custom lightweight protocol)
2. **Go Backend ↔ Frontend**: SSE with ag-ui-compatible event naming (no external ag-ui dependency)

The Go backend acts as a translator between these two layers.

## Layer 1: Go Backend ↔ Python Agent Protocol

### Request (Go → Python)

```
POST http://agent-{type}:{port}/run
Content-Type: application/json

{
  "run_id": "uuid",
  "source_path": "/tmp/sources/abc123",
  "config": {
    // agent-specific configuration
  },
  "prior_findings": [...],
  "lineage_checks_requested": { "schema": 1, "rows": [...] },
  "accepts_mapping": 1
}
```

`lineage_checks_requested` is optional and omitted entirely when the backend has
nothing to ask; see [Lineage evidence checks](#lineage-evidence-checks-feature-0091-versioned)
below.

`accepts_mapping` is written by the backend's agent proxy, for the OWASP agent
only; see [Mapping result (v1)](#mapping-result-v1-feature-0096) below. It is
never part of `config`: the proxy strips an `accepts_mapping` key from every
agent's `config` (escaped spellings included), and the shared transport passes
the top-level field only to a run handler that declares an `accepts_mapping`
parameter.

### Response (Python → Go via SSE)

The Python agent responds with `Content-Type: text/event-stream` and emits events:

```
event: agent_start
data: {"agent_name": "ChaosEngineeringAuditor", "run_id": "uuid"}

event: tool_call
data: {"tool": "list_files", "args": {"path": "/tmp/sources/abc123"}}

event: tool_result
data: {"tool": "list_files", "result": ["main.go", "handler.go", ...]}

event: thinking
data: {"content": "Analyzing retry patterns in main.go..."}

event: finding
data: {"severity": "high", "category": "retry-pattern", "title": "Missing retry logic", ...}

event: progress
data: {"files_analyzed": 12, "total_files": 42, "findings_count": 3}

event: result
data: {"findings": [...], "summary": "...", "score": 72}

event: agent_end
data: {"run_id": "uuid", "status": "completed"}
```

### Lineage evidence checks (feature 0091, versioned)

Absence from an LLM result is not evidence that the code was repaired: the
prior-findings block asks the model to skip known issues, so it complies and the
finding is missing from a scan that never disagreed with it. The evidence quote
that could settle the question never leaves the agent process, so the backend
cannot re-verify anything — it **asks**, and the agent **answers**.

The **request** gains one optional key. Rows are LLM-tier lineage rows only;
deterministic rows keep the unchanged present/absent rule and are never sent.

```json
"lineage_checks_requested": {
  "schema": 1,
  "rows": [
    { "lineage_id": "…", "fingerprint_v2": "…", "rel_path": ".vscode/tasks.json",
      "line_start": 7, "line_end": 7, "quote_hash": "sha256:…",
      "status": "open" | "fixed", "file_hash": "sha256:…" }
  ]
}
```

The **`result` event** gains three keys, emitted on **every** scan whether or not
anything was asked:

```json
"result_schema": 2,
"pruned_dirs": ["node_modules", "src/__pycache__"],
"lineage_checks": [
  { "lineage_id": "…",
    "outcome": "confirmed" | "reanchored" | "ambiguous" | "gone" | "unconfirmable",
    "reason": "…", "line_start": 7, "line_end": 7, "file_hash": "sha256:…" }
]
```

* `result_schema` is the handshake. Absent (or `< 2`) means an agent that predates
  0091: the backend must then treat the scan's scope as unknown and perform no
  LLM-tier and no pruned-dir closures for it. That is why the key is
  unconditional — emitting it only when asked a question would silently disable
  closure for every ordinary scan.
* `pruned_dirs` are **root-relative** prefixes the walker did not descend into.
  Without them "this scan proved nothing is there" is indistinguishable from
  "this scan never looked", and the second would close every row beneath.
* `lineage_checks` answers every requested row, in request order. A requested row
  that comes back with no check is read as `unconfirmable`, so a dropped row can
  never close a finding.
* `gone` is the only outcome that closes anything. Every failure that is a fact
  about the **checker** rather than the **code** — a lost quote, an unreadable or
  oversize file, a crashing verifier — resolves to `unconfirmable` instead.
* The evidence quote itself never appears on the wire in any configuration; the
  lineage row carries only `quote_hash`.

**How the request reaches the runner.** `lineage_checks_requested` is a field on
`shared.models.audit_request.AuditRequest` — it has to be declared there, because
pydantic drops an undeclared key silently and the payload would vanish at the door
with both ends of the wire still looking correct. The transport then binds it into
the run's context (`shared.lineage_context.set_lineage_checks_requested`), the same
way the cancel token and the broker token are bound, and `run_combined_audit` reads
it from there. **An agent does not forward it**: `run_audit(run_id, source_path,
config, prior_findings)` keeps its four-argument shape, and a new agent gets the
evidence pass for free.

**The key names are pinned across the two languages** by one shared fixture,
`agents/shared/tests/contract/0091_lineage_wire.json`, asserted against by
`backend/internal/agui/wire_contract_0091_test.go` and
`agents/shared/tests/e2e/test_0091_wire_seam.py`. Every field above is optional on
both sides, so a rename does not error anywhere — it reads as "absent", which is a
legal and quiet wrong answer. Rename a key in one language and that language's
suite fails against the fixture; edit the fixture to match and the other language's
suite fails instead.

### Mapping result (v1, feature 0096)

A **mapping agent** (registry `Kind: "mapper"`) categorises other agents' findings
instead of detecting its own. The OWASP agent is one: it receives the
CWE-categorised findings of the scan phase as `prior_findings` and answers with
its edition's CWE→category table. The backend applies that table to the run's
final, deduplicated finding set, so every CWE-categorised finding carries its
OWASP labels (`compliance_labels`) and nothing is persisted twice.

**Negotiation.** The backend's agent proxy adds `"accepts_mapping": 1` as a
**top-level** field of the OWASP agent's `/run` body — not inside `config`, which
carries only the backend-owned `cwe_stage_status` and the user's `edition` /
`categories`:

```json
{"run_id": "…", "source_path": "…", "accepts_mapping": 1,
 "config": {"cwe_stage_status": "completed", "edition": "2025", "categories": ["A07"]},
 "prior_findings": ["…"]}
```

It is out of band because a pre-0096 backend forwards arbitrary user `config`
keys to agents: a capability read from `config` would let a user switch the
agent into mapping mode against a backend that reads its zero-finding answer as
"every OWASP issue was fixed" and closes OWASP lineage. So the agent reads the
top-level field only and ignores `config.accepts_mapping`, and this backend
strips that key from every agent's `config` anyway.

The agent answers with a mapping **only** when the field is the JSON integer `1`;
absent, `0`, `true`, `1.0`, `"1"` or any other version gets the legacy answer
(one OWASP copy row per mapped CWE finding). The mode is negotiated, never
guessed from the shape of the result:

| Backend | Agent | Outcome |
|---|---|---|
| sends `accepts_mapping: 1` | speaks v1 | mapping mode |
| sends `accepts_mapping: 1` | predates v1 | legacy copies (the field is ignored) |
| does not send it | speaks v1 | legacy copies, unchanged |

**The `result` event in mapping mode** carries no findings and no `finding`
events precede it:

```json
{
  "findings": [],
  "findings_count": 0,
  "score": 78.1,
  "summary": "Mapped 2 finding(s) into 2/2 OWASP Top 10:2025 categories.",
  "owasp_coverage": {"edition": "2025", "cwe_stage_status": "completed", "categories": ["..."]},
  "mapping": {
    "version": 1,
    "framework": "owasp",
    "edition": "2025",
    "selected": ["A05", "A07"],
    "table": {
      "CWE-798": [{"id": "A07", "name": "Authentication Failures"}],
      "CWE-89":  [{"id": "A05", "name": "Injection"}]
    }
  }
}
```

* The **presence of the `mapping` member**, whatever its value (`null` and an
  invalid object included), is the mode marker. The backend decodes it with Go
  `encoding/json`, so the member name (and the names of the members inside it)
  is matched case-insensitively: `"Mapping"` is the same marker. A mapping-mode result persists
  none of the rows it carries; an invalid mapping labels nothing and never falls
  back to persisting copies. The mode is sticky for the run: a later legacy
  snapshot from the same agent is ignored.
* A mapper agent never reaches lineage, in any mode: its result creates,
  re-sights and closes no lineage row, so an empty `findings` can never be read
  as "fixed". (Legacy copies are persisted as findings but get no lineage.)
* `table` is the **full** edition table — every CWE the edition maps (2025: 249,
  2021: 196) — independent of `selected`, so the backend keeps per-edition labels
  on lineage across category subsets. Entries are `{id, name}` only.
* `selected` echoes the effective `categories` filter (`[]` = all); labels on
  findings are narrowed to it, lineage labels are not. The agent keeps only the
  edition's own ids (deduplicated, in the order given) and, when nothing usable
  is left, sends `["A00"]` — a reserved id no edition defines — meaning "select
  nothing" rather than "all".
* The backend accepts a mapping only from the agent it dispatched as `owasp`, and
  validates it all-or-nothing: `version == 1`, `framework == "owasp"`, a
  four-digit `edition`, at most 2,000 `CWE-<n>` keys, `A<nn>` category ids,
  names of at most 120 runes (Unicode code points), valid UTF-8 and without a
  NUL byte, at most 100 `selected` ids.
* CWE ids are canonicalised without leading zeros (`CWE-089` is `CWE-89`) for
  table keys (colliding keys fold), lookups, `label.cwe`, coverage and lineage.
* Labels are applied after cross-agent dedup. A survivor that absorbed rows of
  other CWE ids is labelled from its own category and theirs, each label's `cwe`
  naming the id it came from.
* `owasp_coverage` is read only from the `owasp` agent's snapshot and exists in
  two copies. The one on the streamed event is **provisional**: the agent's own,
  counted over the priors before dedup, every category counted, no `selected`
  key. The one persisted on the audit is **authoritative**: `mapped_count`,
  names and `cwe_stage_status` stay the agent's; `found_cwes` / `found_count` /
  `status` and `unmapped_cwes` / `unmapped_count` are recounted from the labelled
  final set; each category outside a `selected` subset gets empty found values
  plus `"selected": false` (not checked, rather than clean). A rejected mapping,
  or a manifest for another edition than the mapping, has its found and unmapped
  values cleared and no `selected` key; an unreadable manifest is dropped.
* `summary` reads `Mapped N finding(s) into k/T OWASP Top 10:<edition>
  categories.`: `N` is the number of priors counted by `score`; `T` is the
  number of selected categories in the edition — every category of the edition
  when none is selected (`[]`), and 0 when the filter selects none (`["A00"]`);
  `k` is how many of those `T` categories have at least one found CWE.
* `score` is computed agent-side over the distinct priors that map to at least
  one selected category, before dedup (see
  `agents/owasp/owasp_agent/skills/SKILLS.md`).
* No source text travels in the mapping.

The OWASP agent's actual output for one request is captured in
`agents/owasp/tests/fixtures/owasp_0096_mapping_stream.json`. The agent's suite
fails when its output drifts from the file, and
`backend/test/e2e/owasp_mapping_flow_test.go` replays it through the backend
stream path, so the two sides are tested against the same bytes.

### Health Check

```
GET http://agent-{type}:{port}/health
→ 200 { "status": "healthy", "agent": "chaos_engineering" }
```

### Agent Discovery

```
GET http://agent-{type}:{port}/info
→ 200 {
    "name": "Chaos Engineering Auditor",
    "type": "chaos",
    "description": "Analyzes code for resilience and chaos engineering patterns",
    "config_schema": { ... },  // JSON Schema for agent-specific config
    "skills": ["retry_analysis", "circuit_breaker", "timeout_analysis", ...]
  }
```

## Layer 2: Go Backend ↔ Frontend (SSE Protocol (ag-ui-compatible event naming))

### Connection

The frontend first obtains a short-lived, single-use stream token, then connects:

```
POST /api/audits/{id}/stream-token
Authorization: Bearer <jwt>
→ 200 { "stream_token": "..." }

GET /api/audits/{id}/stream?stream_token=<token>
Accept: text/event-stream
```

Stream tokens expire after 60 seconds and can only be used once. This avoids exposing the long-lived JWT in URL query parameters.

### ag-ui Event Types Used

| Event Type | When Emitted | Purpose |
|-----------|-------------|---------|
| `RunStarted` | Audit begins | Initialize frontend state |
| `StepStarted` | Agent dispatch | Show agent started in timeline |
| `TextMessageStart` | Agent begins outputting | Start message bubble |
| `TextMessageContent` | Agent streaming | Stream analysis text |
| `TextMessageEnd` | Agent finishes a message | Close message bubble |
| `ToolCallStart` | Agent invokes a tool | Show tool activity |
| `ToolCallArgs` | Tool arguments | Display tool input |
| `ToolCallEnd` | Tool completes | Show tool finished |
| `StateDelta` | New finding discovered | Incrementally update findings |
| `StateSnapshot` | All agents complete | Final state with all findings |
| `StepFinished` | Agent completes | Update timeline |
| `RunFinished` | All agents done | Final state, enable actions |
| `RunError` | Error occurs | Display error to user |

### Event Format

Each event follows the ag-ui JSON format:

```
event: RunStarted
data: {"type":"RunStarted","runId":"xyz789","threadId":"t-1"}

event: StepStarted
data: {"type":"StepStarted","stepName":"chaos_engineering","stepId":"s-1"}

event: TextMessageContent
data: {"type":"TextMessageContent","messageId":"m-1","delta":"Checking retry patterns..."}

event: StateDelta
data: {"type":"StateDelta","delta":[{"op":"add","path":"/findings/-","value":{"severity":"high",...}}]}

event: RunFinished
data: {"type":"RunFinished","runId":"xyz789"}
```

## Translation Logic (Go Backend)

The `agui/translator.go` component maps between the two layers:

| Python Agent Event | ag-ui Event |
|-------------------|-------------|
| `agent_start` | `StepStarted` |
| `thinking` | `TextMessageStart` + `TextMessageContent` |
| `tool_call` | `ToolCallStart` + `ToolCallArgs` |
| `tool_result` | `ToolCallEnd` |
| `finding` | `StateDelta` (JSON Patch add to findings array) |
| `progress` | `StateDelta` (update progress counters) |
| `result` | `StateSnapshot` |
| `agent_end` | `StepFinished` |

## Error Handling

- If a Python agent fails, the Go backend emits `StepFinished` with error status and continues with remaining agents
- If all agents fail, `RunError` is emitted
- The frontend gracefully handles partial results (some agents succeeded, some failed)
- Agent HTTP timeouts: 5 minutes per agent (configurable)
- SSE reconnection: disabled — stream tokens are single-use, so the frontend closes the EventSource on error rather than auto-reconnecting
