# Vulture - System Architecture Overview

## Purpose

Vulture is a compliance audit platform that uses AI agents to inspect source code against multiple compliance frameworks. It currently supports Chaos Engineering principles, OWASP guidelines, and SOC2 compliance, with an extensible architecture for adding new audit types.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Frontend (Next.js)                     │
│         CopilotKit + ag-ui protocol client               │
│         Tailwind CSS (agentation.dev aesthetic)           │
└────────────┬──────────────────────┬──────────────────────┘
             │ SSE (ag-ui events)   │ REST (CRUD)
             ▼                      ▼
┌──────────────────────────────────────────────────────────┐
│                  Go Backend (Orchestrator)                │
│  ┌─────────┐ ┌─────────────┐ ┌────────────┐ ┌────────┐ │
│  │ Handlers│ │  Services   │ │  ag-ui SSE │ │ SQLite │ │
│  │ (REST)  │ │ (Business)  │ │ (Encoder)  │ │ (Repo) │ │
│  └─────────┘ └─────────────┘ └────────────┘ └────────┘ │
└────────┬──────────────┬──────────────┬───────────────────┘
         │ HTTP/SSE     │ HTTP/SSE     │ HTTP/SSE
         ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌ ─ ─ ─ ─ ┐
│   Chaos    │ │   OWASP    │ │    SOC2    │   Future
│   Agent    │ │   Agent    │ │   Agent    │ │  Agent   │
│  (Python)  │ │  (Python)  │ │  (Python)  │  (Python)
└────────────┘ └────────────┘ └────────────┘ └ ─ ─ ─ ─ ┘
  FastAPI + OpenAI Agents SDK + LiteLLM (each)
```

## Components

### Frontend (Next.js + CopilotKit)

- **Framework**: Next.js with TypeScript
- **UI Library**: Tailwind CSS with custom warm cream theme
- **Agent Protocol**: ag-ui (CopilotKit React integration)
- **Transport**: Server-Sent Events (SSE) for real-time agent streaming
- **Testing**: Playwright for E2E, Vitest for unit tests

The frontend connects to the Go backend via two channels:
1. **REST API** for CRUD operations (submit sources, start audits, fetch results)
2. **SSE stream** for real-time audit progress using the ag-ui protocol

### Go Backend (Orchestrator)

- **Language**: Go 1.23+
- **Database**: SQLite (via CGO)
- **Role**: Central orchestrator that receives audit requests, manages source code, dispatches work to Python agents, and aggregates results

Key responsibilities:
- Source code ingestion (git clone or local path validation)
- Audit lifecycle management (create, track, complete)
- Agent dispatch and SSE stream aggregation
- ag-ui event translation and forwarding to frontend
- Persistence of audit results

### Python Agent Microservices

- **Framework**: FastAPI with SSE streaming
- **AI SDK**: OpenAI Agents SDK with LiteLLM for model-agnostic LLM access
- **Default Model**: GPT-4o (configurable to Claude, Gemini via LiteLLM)
- **Shared Library**: Common tools (file reader, AST parser, pattern matcher) and transport layer

Each agent is a standalone FastAPI service with:
- Agent definition (name, instructions, tools)
- Compliance-specific skills (@function_tool decorated functions)
- SKILLS.md documenting the agent's capabilities
- SSE streaming endpoint (`POST /run`)

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Frontend | Next.js + Tailwind | Modern React framework with SSR, Tailwind for rapid styling |
| Agent UI Protocol | ag-ui + CopilotKit | Standard protocol for agent-to-UI communication, event-based SSE |
| Backend | Go | Performance, single binary deployment, excellent concurrency for stream aggregation |
| Agent SDK | OpenAI Agents SDK | Code-first agent definition, built-in streaming, multi-model via LiteLLM |
| Database | SQLite | Zero-config, embedded, sufficient for audit result storage |
| Deployment | Docker Compose | Simple multi-service orchestration for Go + Python + Next.js |

## Constraints

- Cyclomatic complexity < 10 for all functions
- 100% test coverage
- E2E tests written before implementation code
- ISO 26262 safety categorization adherence
- DRY principle enforced across all components
