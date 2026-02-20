# CLI Mode - Implementation Status

## Status: PLANNED

## Completed Items
- [x] Backend API endpoints that CLI will consume (auth, audits, sources, memories, stream)
- [x] SSE streaming protocol (ag-ui events)
- [x] Authentication system (JWT tokens)
- [x] Memory system with token optimization

## Remaining Items

### CLI Binary
- [ ] Cobra root command setup (`backend/cmd/vulture-cli/main.go`)
- [ ] `vulture login` command with credential prompt
- [ ] `vulture logout` command
- [ ] `vulture scan <path|url>` with SSE terminal streaming
- [ ] `vulture scan --type` flag for audit type selection
- [ ] `vulture scan --config` flag for custom audit configuration
- [ ] `vulture status <audit-id>` command
- [ ] `vulture status --latest` flag
- [ ] `vulture list` command with formatted table
- [ ] `vulture memories search <query>` command
- [ ] `vulture memories status <id> <status>` command
- [ ] `vulture config set/show` commands

### Shared Client Library
- [ ] HTTP client with auth token injection (`backend/pkg/client/client.go`)
- [ ] SSE stream reader for terminal output (`backend/pkg/client/sse.go`)
- [ ] Config file management (`~/.vulture/config.json`)

### Terminal UI
- [ ] Color-coded severity output (lipgloss)
- [ ] Progress indicators during scanning
- [ ] Formatted results tables
- [ ] Token savings display

### Testing
- [ ] Unit tests for each command
- [ ] Integration tests with mock server
- [ ] E2E test: login -> scan -> status flow

## Prerequisites
- Backend API (COMPLETE)
- Authentication system (COMPLETE)
- Memory system (COMPLETE)
