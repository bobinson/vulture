# Vulture - Data Flow

## End-to-End Audit Flow

### Step 1: Source Submission

```
User → Frontend (SourceInput)
  → POST /api/sources { type: "git", url: "https://github.com/org/repo" }
  → Go Backend: source_service.Ingest()
    → gitutil.Clone() to /tmp/sources/{hash}/
    → fileutil.Walk() to count and categorize files
  ← Response: { source_id: "abc123", path: "/tmp/sources/abc123", file_count: 142 }
```

For local paths:
```
  → POST /api/sources { type: "local", path: "/path/to/code" }
  → Go Backend: source_service.Validate()
    → Verify path exists and is readable
    → fileutil.Walk() to count and categorize files
  ← Response: { source_id: "def456", path: "/path/to/code", file_count: 89 }
```

### Step 2: Audit Initiation

```
User → Frontend (AuditTypeSelector + Submit)
  → POST /api/audits {
      source_id: "abc123",
      types: ["chaos", "owasp", "soc2"],
      config: {
        soc2: { clauses: ["CC6", "CC7", "CC8"] }
      }
    }
  → Go Backend: audit_service.Start()
    → Creates audit record in SQLite (status: "running")
    → Returns audit_id immediately (non-blocking)
  ← Response: { audit_id: "xyz789", status: "running" }
```

### Step 3: SSE Stream Connection

```
Frontend → useAgentStream("xyz789")
  → GET /api/audits/xyz789/stream
  → Go Backend: stream_handler
    → Sets headers: Content-Type: text/event-stream, Cache-Control: no-cache
    → Emits ag-ui event: RunStarted { runId: "xyz789" }
```

### Step 4: Parallel Agent Dispatch

```
Go Backend (concurrent goroutines for each audit type):

  goroutine 1: POST http://agent-chaos:8001/run
    { run_id: "xyz789", source_path: "/tmp/sources/abc123", config: {} }

  goroutine 2: POST http://agent-owasp:8002/run
    { run_id: "xyz789", source_path: "/tmp/sources/abc123", config: {} }

  goroutine 3: POST http://agent-soc2:8003/run
    { run_id: "xyz789", source_path: "/tmp/sources/abc123",
      config: { clauses: ["CC6", "CC7", "CC8"] } }
```

### Step 5: Agent Processing (per agent)

```
Python Agent (e.g., Chaos Engineering):
  → Receives AuditRequest via POST /run
  → Runner.run_streamed(chaos_agent, input)
  → Agent invokes tools:
    → list_files(source_path) → get file inventory
    → read_file(path) → read source files
    → parse_ast(path) → analyze code structure
    → check_retry_patterns(code) → skill-specific analysis
    → check_circuit_breaker(code) → skill-specific analysis
  → Agent reasons about findings
  → Agent produces structured AuditResult:
    { findings: [...], summary: "...", score: 72 }
  → FastAPI streams SSE events throughout
```

### Step 6: Event Aggregation + Forwarding

```
Go Backend (stream_service, per agent stream):
  ← Receives SSE from Python agent
  → Translates to ag-ui events:
    → StepStarted { stepName: "chaos_engineering" }
    → TextMessageStart { messageId: "msg-1" }
    → TextMessageContent { delta: "Analyzing retry patterns..." }
    → ToolCallStart { toolCallId: "tc-1", toolName: "check_retry_patterns" }
    → ToolCallEnd { toolCallId: "tc-1" }
    → StateDelta { findings: [{ severity: "high", ... }] }
    → StepFinished { stepName: "chaos_engineering" }
  → Forwards each event to frontend via SSE

When all agents complete:
  → StateSnapshot { all_findings: [...], scores: {...} }
  → RunFinished { runId: "xyz789" }
```

### Step 7: Frontend Rendering

```
React (via useAgent hook receives ag-ui events):
  → AuditTimeline: shows step progress (chaos ✓, owasp ◌, soc2 ...)
  → AgentStream: renders terminal-style streaming text per agent
  → FindingsTable: populates incrementally as StateDelta events arrive
  → ScoreCard: displays scores from StateSnapshot
  → SeverityBadge: color-coded severity (critical/high/medium/low)
```

### Step 8: Persistence

```
Go Backend (after RunFinished):
  → audit_repo.SaveResult(audit_id, findings, scores)
  → SQLite update: audit.status = "completed", audit.completed_at = now()
  → Results accessible via GET /api/audits/xyz789
```

## Data Models

### Source
```
{
  id: string (UUID)
  type: "git" | "local"
  url?: string           // for git sources
  path: string           // filesystem path (cloned or local)
  file_count: int
  created_at: timestamp
}
```

### Audit
```
{
  id: string (UUID)
  source_id: string
  types: string[]        // ["chaos", "owasp", "soc2"]
  config: object         // per-type configuration
  status: "pending" | "running" | "completed" | "failed"
  findings: Finding[]
  scores: { [type]: number }
  created_at: timestamp
  completed_at?: timestamp
}
```

### Finding
```
{
  id: string (UUID)
  audit_id: string
  agent_type: string     // "chaos", "owasp", "soc2"
  severity: "critical" | "high" | "medium" | "low" | "info"
  category: string       // e.g., "retry-pattern", "sql-injection", "cc6-access"
  title: string
  description: string
  file_path: string
  line_start: int
  line_end: int
  recommendation: string
  references: string[]   // links to standards/docs
}
```
