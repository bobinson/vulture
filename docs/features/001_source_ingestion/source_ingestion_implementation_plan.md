# Source Ingestion - Implementation Plan

## Overview

Source ingestion is the entry point for all audits. It accepts source code from two input methods -- git repository URLs and local filesystem paths -- validates them, prepares the source for agent consumption, and returns a source identifier for subsequent audit requests.

## Requirements

1. Accept git repository URLs (HTTPS and SSH) and clone them to a temporary directory
2. Accept local filesystem paths and validate they exist and are readable
3. Walk the file tree to count and categorize files by language/type
4. Return a unique source ID, resolved filesystem path, and file metadata
5. Reject invalid inputs with descriptive error messages
6. Clean up cloned repositories when no longer referenced by any audit
7. Enforce maximum repository size limits to prevent resource exhaustion

## Technical Design

### API Endpoint

```
POST /api/sources
Content-Type: application/json

// Git source
{ "type": "git", "url": "https://github.com/org/repo.git" }

// Local path
{ "type": "local", "path": "/absolute/path/to/code" }
```

### Response

```json
{
  "id": "uuid",
  "type": "git",
  "url": "https://github.com/org/repo.git",
  "path": "/tmp/sources/abc123",
  "file_count": 142,
  "languages": { "go": 45, "python": 30, "typescript": 67 },
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Components

| Component | File | Responsibility |
|-----------|------|----------------|
| Handler | `backend/internal/handler/source_handler.go` | HTTP request parsing, validation, response formatting |
| Service | `backend/internal/service/source_service.go` | Business logic: clone/validate, walk, create record |
| Repository | `backend/internal/repository/source_repo.go` | SQLite CRUD for source records |
| Model | `backend/internal/model/source.go` | Source struct and validation |
| Git Utility | `backend/pkg/gitutil/clone.go` | Git clone with depth=1, timeout, size check |
| File Utility | `backend/pkg/fileutil/walk.go` | File tree walking, language detection, counting |

### Processing Flow

1. Handler parses and validates the request body
2. Service dispatches to `Ingest()` (git) or `Validate()` (local)
3. For git: `gitutil.Clone()` performs shallow clone to `/tmp/sources/{uuid}/`
4. For local: verify path exists, is a directory, is readable
5. `fileutil.Walk()` traverses the directory, counts files, detects languages by extension
6. Service creates a Source record in SQLite via the repository
7. Handler returns the Source as JSON

### Validation Rules

- Git URLs must match `^https?://` or `^git@` patterns
- Local paths must be absolute (start with `/`)
- Local paths must exist and be directories
- Git clone must complete within 60 seconds
- Cloned repository must not exceed 500MB
- Path traversal attacks prevented: local paths resolved to canonical form

### Error Responses

| Condition | HTTP Status | Error Code |
|-----------|-------------|------------|
| Invalid JSON body | 400 | `invalid_request` |
| Missing required fields | 400 | `validation_error` |
| Invalid git URL format | 400 | `invalid_url` |
| Local path does not exist | 404 | `path_not_found` |
| Local path is not a directory | 400 | `not_a_directory` |
| Git clone failed | 502 | `clone_failed` |
| Repository too large | 413 | `source_too_large` |
| Clone timeout | 504 | `clone_timeout` |

## API Changes

This feature introduces the `POST /api/sources` endpoint. No existing endpoints are modified.

## Testing Strategy

### E2E Tests (`backend/test/e2e/source_test.go`)

- Submit a valid git URL and verify the response contains source ID, path, and file count
- Submit a valid local path and verify the response
- Submit an invalid git URL and verify 400 error
- Submit a non-existent local path and verify 404 error
- Submit a path that is a file (not directory) and verify 400 error
- Verify cloned files are accessible at the returned path

### Unit Tests

- `source_handler_test.go`: request parsing, validation, error formatting
- `source_service_test.go`: business logic with mocked repository and utilities
- `source_repo_test.go`: SQLite CRUD operations
- `gitutil/clone_test.go`: clone behavior, timeout, size limits
- `fileutil/walk_test.go`: file counting, language detection, edge cases

## Dependencies

- `os/exec` for git clone (or `go-git` if needed)
- SQLite driver for persistence
- No external service dependencies -- this feature is self-contained
