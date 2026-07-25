# Source Ingestion - Implementation Status

## Status: In Progress

## Checklist

### E2E Tests
- [x] E2E test: submit valid git URL and receive source response (`backend/test/e2e/source_ingest_test.go`)
- [x] E2E test: submit valid local path and receive source response
- [x] E2E test: submit invalid git URL and receive 400 error
- [x] E2E test: submit non-existent local path and receive 404 error
- [x] E2E test: submit file path (not directory) and receive 400 error
- [ ] E2E test: verify cloned files exist at returned path

### Implementation
- [x] Source model (`backend/internal/model/source.go`)
- [x] Source repository (`backend/internal/repository/sqlite_repo.go`, `postgres_repo.go`)
- [x] Git clone utility (`backend/pkg/gitutil/clone.go`)
- [x] File walk utility (`backend/pkg/fileutil/walker.go`)
- [x] Source service (`backend/internal/service/source_service.go`)
- [x] Source handler (`backend/internal/handler/source_handler.go`)
- [x] Route registration in server (`backend/internal/server/server.go`)
- [x] Docker volume mounts for local path access (`docker-compose.yml`)

### Unit Tests
- [x] Source handler unit tests (`backend/internal/handler/handler_test.go`)
- [ ] Source service unit tests
- [x] Source repository unit tests (`backend/internal/repository/sqlite_repo_test.go`)
- [x] Git clone utility unit tests (`backend/pkg/gitutil/clone_test.go`)
- [x] File walk utility unit tests (`backend/pkg/fileutil/walker_test.go`)

### Quality Gates
- [ ] 100% test coverage verified
- [ ] Cyclomatic complexity < 10 verified
- [ ] golangci-lint passes
- [ ] E2E suite passes after integration

### Notes

- Backend uses PostgreSQL with pgvector extension (via `postgres_repo.go`) instead of SQLite for production
- SQLite remains available as a fallback via `sqlite_repo.go`
- Docker containers mount `/home:/home:ro` for local path scanning access
- Source deduplication (`FindSourceByPath`) prevents duplicate entries for the same path
