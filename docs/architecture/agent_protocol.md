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
  "lineage_checks_requested": { "schema": 1, "rows": [...] }
}
```

`lineage_checks_requested` is optional and omitted entirely when the backend has
nothing to ask; see [Lineage evidence checks](#lineage-evidence-checks-feature-0091-versioned)
below.

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
