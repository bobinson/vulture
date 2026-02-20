# Streaming UI - Implementation Plan

## Overview

The streaming UI provides real-time visualization of audit progress using the ag-ui protocol. It connects to the Go backend via Server-Sent Events (SSE), renders agent output in a terminal-style interface, and progressively displays findings as they are discovered. The UI uses CopilotKit for ag-ui protocol integration and follows the agentation.dev aesthetic -- warm cream theme, compact sidebar, intuitive layout.

## Requirements

1. Establish SSE connection to `GET /api/audits/:id/stream` and process ag-ui events
2. Render agent output in a terminal-style streaming text view
3. Display audit timeline showing per-agent step progress
4. Progressively populate a findings table as `StateDelta` events arrive
5. Show score cards when `StateSnapshot` is received
6. Handle errors gracefully with partial result display
7. Auto-reconnect on connection loss using `Last-Event-ID`
8. Responsive design: desktop-first with mobile support

## Technical Design

### Component Architecture

```
AuditPage
  ├── AuditSidebar          # Compact sidebar: source info, audit config, agent list
  ├── AuditContent
  │   ├── AuditTimeline     # Step progress per agent (started, running, completed, failed)
  │   ├── AgentStreamPanel  # Terminal-style streaming output (tabbed per agent)
  │   │   └── AgentStream   # Single agent's streaming text
  │   ├── FindingsTable     # Incrementally populated findings with severity badges
  │   │   └── FindingRow    # Individual finding with expandable details
  │   └── ScorePanel        # Score cards per audit type + overall
  │       └── ScoreCard     # Single score with gauge visualization
  └── AuditFooter           # Status bar: connection state, elapsed time, finding count
```

### ag-ui Protocol Integration

Using CopilotKit's `useCoAgent` hook for ag-ui event handling:

```typescript
// src/hooks/useAuditStream.ts
import { useCoAgent } from "@copilotkit/react-core";

export function useAuditStream(auditId: string) {
  const { state, running, messages } = useCoAgent({
    name: "vulture-audit",
    url: `${API_URL}/api/audits/${auditId}/stream`,
  });

  return {
    findings: state?.findings ?? [],
    scores: state?.scores ?? {},
    steps: state?.steps ?? [],
    messages,
    isRunning: running,
  };
}
```

### Event Handling

| ag-ui Event | UI Update |
|-------------|-----------|
| `RunStarted` | Initialize audit state, show "Audit started" in timeline |
| `StepStarted` | Add agent to timeline as "running", create agent tab |
| `TextMessageStart` | Begin new message bubble in agent stream |
| `TextMessageContent` | Append delta text to current message (streaming effect) |
| `TextMessageEnd` | Finalize message bubble |
| `ToolCallStart` | Show tool activity indicator in agent stream |
| `ToolCallEnd` | Mark tool as completed |
| `StateDelta` | Add finding to findings table, increment counter |
| `StateSnapshot` | Set final state: all findings, scores |
| `StepFinished` | Mark agent as completed/failed in timeline |
| `RunFinished` | Show completion state, enable export actions |
| `RunError` | Display error banner, show partial results if available |

### Theme and Styling

Following the agentation.dev aesthetic with Tailwind CSS:

```
Colors:
  Background:  #F6F5F4 (warm cream)
  Surface:     #FFFFFF (white cards)
  Accent:      #3b82f6 (blue)
  Success:     #22c55e (green)
  Warning:     #f59e0b (amber)
  Error:       #ef4444 (red)
  Text:        #1f2937 (gray-800)
  Muted:       #6b7280 (gray-500)

Typography:
  Headings:    Inter/system sans-serif
  Agent output: JetBrains Mono/monospace (terminal style)

Layout:
  Sidebar:     240px fixed, collapsible
  Content:     Fluid, max-width 1200px
  Findings:    Full-width table with sticky header
```

### Terminal-Style Agent Output

The `AgentStream` component renders agent messages in a terminal aesthetic:

- Monospace font with syntax highlighting for code snippets
- Green text for agent "thinking" messages
- Blue text for tool invocations
- Red text for findings
- Dimmed text for progress updates
- Auto-scroll to bottom with scroll-lock toggle

### SSE Reconnection

```typescript
// Built into CopilotKit, but custom fallback:
const eventSource = new EventSource(streamUrl);
eventSource.onerror = () => {
  // Reconnect with Last-Event-ID for resumption
  setTimeout(() => reconnect(lastEventId), 1000);
};
```

### State Management

Audit state managed via CopilotKit's built-in state from ag-ui events:

```typescript
interface AuditState {
  status: "pending" | "running" | "completed" | "failed";
  steps: StepState[];          // Per-agent progress
  findings: Finding[];         // Incrementally populated
  scores: Record<string, number>;  // Per-type scores
  messages: AgentMessage[];    // Streaming text per agent
}
```

## API Changes

No new API endpoints. This feature consumes:
- `GET /api/audits/:id/stream` (SSE, ag-ui events)
- `GET /api/audits/:id` (REST, for initial state on reconnect)
- `GET /api/agents` (REST, for agent metadata)

## Testing Strategy

### E2E Tests (Playwright, `frontend/tests/e2e/`)

- Connect to a running audit and verify timeline updates
- Verify streaming text appears in agent output panel
- Verify findings table populates as StateDelta events arrive
- Verify score cards appear after RunFinished
- Verify error banner on RunError
- Verify reconnection after simulated disconnect
- Verify responsive layout at mobile and desktop breakpoints

### Unit Tests (Vitest, `frontend/src/__tests__/`)

- `useAuditStream` hook: test state updates for each event type
- `AuditTimeline`: test step rendering for various states
- `AgentStream`: test message rendering and auto-scroll
- `FindingsTable`: test incremental row addition, sorting, filtering
- `ScoreCard`: test score display and gauge rendering
- `SeverityBadge`: test color mapping for each severity level

## Dependencies

- `@copilotkit/react-core`: ag-ui protocol React integration
- `next`: Next.js framework
- `tailwindcss`: Utility-first CSS
- No additional UI component libraries -- custom components with Tailwind
