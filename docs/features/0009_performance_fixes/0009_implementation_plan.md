# 0009 Performance Fixes Implementation Plan

## Overview
Fix 53 performance issues identified across all components: Go backend, Python agents, React frontend, and infrastructure.

## Approach
- RED/GREEN TDD: Tests first, then implementation
- DRY: No duplicated logic
- Cyclomatic complexity < 5
- O(1) lookups where possible, O(n) only where unavoidable

## Batches

### Batch 1: Frontend Critical+High (#1,2,9,10,11)
- Fix `useAgentStream` SSE listener memory leak
- Fix `handleSSEEvent` recreation causing duplicate handlers
- Bound `lines` array growth
- Fix broken dependency arrays
- Fix `FindingsTable` key including page index

### Batch 2: Go Backend Critical (#3,4,5)
- Increase SQLite `MaxOpenConns` for concurrent reads
- Eliminate N+1 subqueries in `ListAudits`
- Add missing indexes on hot query paths

### Batch 3: Go Backend High (#12-17)
- Add semaphore+context to `embedAndLink` goroutines
- Add body-read timeout on agent HTTP calls
- Reduce SSE buffer from 16MB to 64KB initial
- Cache fingerprints to avoid redundant SHA256
- Add prepared statements
- Increase SSE event channel buffer

### Batch 4: Python Critical+High (#6,18-21)
- Pre-compile regex in catalog_detector
- Single `stat()` call in file prioritization
- Replace `asyncio.new_event_loop()` with `asyncio.run()`
- Pass pre-scanned file list to skills
- Cache `prior_context.split()` result

### Batch 5: Infrastructure (#7,8,22-25,47-53)
- Docker health checks for all services
- Resource limits on all containers
- Restart backoff policies
- PostgreSQL tuning
- Connection pool sizing
- Missing DB indexes
- CI caching (npm, pip, Docker)
- Makefile parallel builds
- Dockerfile layer optimization
- Nginx tuning

### Batch 6: Medium Frontend (#26-34)
- Polling backoff after completion
- Remove dual filtering
- Memoize row callbacks
- Lazy-load i18n locales
- Request deduplication

### Batch 7: Medium Go (#35-41)
- Cache fingerprints in Finding struct
- Pre-normalize strings in dedup
- Reuse health check HTTP client
- Replace LIKE with keyword table
- Use SQL AVG() for score computation

### Batch 8: Medium Python (#42-46)
- Tune ThreadPoolExecutor workers
- Combine regex patterns in skills
- Single token estimation pass
- Early exit in file packing

## Rollback
Each batch is an independent commit. Revert individual commits if issues arise.
