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
  "prior_findings": [...]
}
```

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
