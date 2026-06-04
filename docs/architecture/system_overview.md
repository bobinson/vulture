# Vulture - System Architecture Overview

## Purpose

Vulture is a compliance audit platform that uses AI agents to inspect source code against multiple compliance frameworks. It currently supports Chaos Engineering, OWASP Top 10, CWE, SOC2, XSS scanning, NIST SSDF, endpoint discovery, and formal verification (Prove), with an extensible architecture for adding new audit types.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Frontend (React 19 + Vite 7)                │
│       Native EventSource + SSE streaming client          │
│         Tailwind CSS (agentation.dev aesthetic)           │
└────────────┬──────────────────────┬──────────────────────┘
             │ SSE (events)         │ REST (CRUD)
             ▼                      ▼
┌──────────────────────────────────────────────────────────┐
│                  Go Backend (Orchestrator)                │
│  ┌─────────┐ ┌─────────────┐ ┌────────────┐ ┌────────┐ │
│  │ Handlers│ │  Services   │ │    SSE     │ │Postgres│ │
│  │ (REST)  │ │ (Business)  │ │ (Encoder)  │ │ (Repo) │ │
│  └─────────┘ └─────────────┘ └────────────┘ └────────┘ │
└────────┬──────────────┬──────────────┬───────────────────┘
         │ HTTP/SSE     │ HTTP/SSE     │ HTTP/SSE
         ▼              ▼              ▼
  8 Agent Types (each: FastAPI + OpenAI Agents SDK + LiteLLM)
┌───────┐┌───────┐┌───────┐┌───────┐┌───────┐┌───────┐┌───────┐┌────────┐
│ Chaos ││ OWASP ││ SOC2  ││  CWE  ││ Prove ││  XSS  ││ SSDF  ││Discover│
└───────┘└───────┘└───────┘└───────┘└───────┘└───────┘└───────┘└────────┘
```

## Components

### Frontend (React 19 + Vite 7)

- **Framework**: React 19 with TypeScript (Vite 7)
- **UI Library**: Tailwind CSS with custom warm cream theme
- **Streaming**: Native EventSource API for Server-Sent Events (SSE)
- **Transport**: Server-Sent Events (SSE) for real-time agent streaming
- **Testing**: Playwright for E2E, Vitest for unit tests

The frontend connects to the Go backend via two channels:
1. **REST API** for CRUD operations (submit sources, start audits, fetch results)
2. **SSE stream** for real-time audit progress using Server-Sent Events

### Go Backend (Orchestrator)

- **Language**: Go 1.24+
- **Database**: PostgreSQL with pgvector extension (SQLite fallback available)
- **Role**: Central orchestrator that receives audit requests, manages source code, dispatches work to Python agents, and aggregates results

Key responsibilities:
- Source code ingestion (git clone or local path validation)
- Audit lifecycle management (create, track, complete)
- Agent dispatch and SSE stream aggregation
- SSE event translation and forwarding to frontend
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
| Frontend | React 19 + Vite 7 + Tailwind | Modern React SPA with Vite, Tailwind for rapid styling |
| Streaming | Native EventSource (SSE) | Standard browser API for Server-Sent Events, no external dependencies |
| Backend | Go | Performance, single binary deployment, excellent concurrency for stream aggregation |
| Agent SDK | OpenAI Agents SDK | Code-first agent definition, built-in streaming, multi-model via LiteLLM |
| Database | PostgreSQL + pgvector | Vector similarity search for audit memory, production-grade persistence |
| Deployment | Docker Compose | Simple multi-service orchestration for Go + Python + React |

## Engineering targets

These are the standards the project holds itself to (monitored in CI,
not all hard-gated — a tail of older code still has work to do):

- Low cyclomatic complexity (target < 10 per function)
- High, comprehensive test coverage
- E2E tests written before implementation code
- DRY principle across all components

Note: Vulture is application software. It does not claim ISO 26262 /
DO-178C compliance for its own codebase — those are *audit frameworks*
the agents evaluate other code against.
