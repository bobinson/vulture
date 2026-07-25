# Memory System - Implementation Plan

## Overview
pgvector-based memory system that stores audit findings as embeddings for semantic search, auto-linking related findings, token optimization via deduplication, and remediation tracking.

## Architecture

### Storage Layer
- **PostgreSQL + pgvector**: `audit_memories` table with `vector(1536)` embedding column
- **HNSW Index**: `CREATE INDEX ON audit_memories USING hnsw (embedding vector_cosine_ops)` for fast nearest-neighbor search
- **Edge Graph**: `memory_edges` table links related memories with typed relationships and strength scores

### Embedding Pipeline
- **Model**: OpenAI `text-embedding-3-small` (1536 dimensions)
- **Input**: Concatenated `title + content + keywords + file_paths`
- **Auto-linking**: Background goroutine finds top-3 similar memories (>0.75 cosine similarity) and creates edges

### Memory Types
| Type | Description |
|------|-------------|
| same_issue | Identical or near-identical finding |
| related_compliance | Different compliance frameworks, same underlying concern |
| supersedes | Newer finding replaces older one |
| derived_from | Finding discovered from a related issue |
| contradicts | Conflicting findings (e.g., different severity for same issue) |
| remediated_by | Resolution link |
| escalates_to | Severity escalation chain |

### Token Optimization
- **Deduplication**: `build_prior_context()` deduplicates by title+file_path
- **Filtering**: Excludes resolved/false_positive findings
- **Compact format**: Single-letter severity + file basename (~15 tokens/finding vs ~30)
- **Cap**: Maximum 10 findings in context to limit token usage
- **DB dedup**: `DISTINCT ON (title, finding_type)` in SQL queries

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/memories/search?q=&limit=` | Semantic search (empty q returns recent) |
| GET | `/api/memories/:id` | Get memory with edges |
| GET | `/api/memories/:id/edges` | Get related memories |
| PATCH | `/api/memories/:id` | Update remediation status |

## Components

### Backend (Go)
- `repository/memory_repo.go` - PostgreSQL queries with pgvector
- `service/memory_service.go` - Store, embed, auto-link, search
- `handler/memory_handler.go` - HTTP handlers
- `embedding/client.go` - OpenAI embedding client

### Python Agents
- `shared/tools/memory_client.py` - HTTP client for memory access + token optimization
- `shared/audit_runner.py` - Emits token_savings SSE events

### Frontend
- `pages/Memories.tsx` - Memory Bank page with search, detail panel, remediation
- `components/results/TokenSavings.tsx` - Token savings badge component
- `hooks/useAgentStream.ts` - Handles token_savings StateDelta events

## Dependencies
- PostgreSQL 17 with pgvector extension
- OpenAI API key (for embeddings)
- Go `pgx` driver with pgvector support

## Testing
- Go: Unit tests for memory_repo, memory_service, memory_handler
- Python: 24 tests for memory_client (estimate_tokens, dedup, filter, build_prior_context)
- Frontend: 16 tests for Memories page, TokenSavings component
