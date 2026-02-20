# CLI Mode - Implementation Plan

## Overview
Command-line interface for quick-start audit workflows. Enables `vulture login` followed by `vulture scan <folder-or-git-url>` for rapid compliance scanning without the web UI.

## Architecture

### CLI Flow
```
vulture login → prompt email/password → POST /api/auth/login → store token in ~/.vulture/config.json
vulture scan <path|url> → POST /api/sources → POST /api/audits → SSE stream → terminal output
vulture status <audit-id> → GET /api/audits/:id → formatted results
vulture memories search <query> → GET /api/memories/search → formatted list
```

### Technology
- **Language**: Go (same repo as backend, separate `cmd/vulture-cli/` binary)
- **CLI Framework**: `cobra` for command parsing
- **Config Storage**: `~/.vulture/config.json` with token, server URL, default settings
- **Output**: Rich terminal output with color-coded severity (using `lipgloss` or `termenv`)

## Commands

| Command | Description |
|---------|-------------|
| `vulture login` | Authenticate and store JWT token |
| `vulture logout` | Remove stored credentials |
| `vulture scan <path\|url>` | Submit source and run all audit types |
| `vulture scan <path\|url> --type chaos,owasp` | Run specific audit types |
| `vulture scan <path\|url> --config soc2.clauses=CC6,CC7` | Custom audit config |
| `vulture status <audit-id>` | Check audit status and results |
| `vulture status --latest` | Show most recent audit |
| `vulture list` | List recent audits with status |
| `vulture memories search <query>` | Search memory bank |
| `vulture memories status <id> <status>` | Update remediation status |
| `vulture config set server <url>` | Set backend server URL |
| `vulture config show` | Display current configuration |

## Components

### CLI Binary (`backend/cmd/vulture-cli/`)
- `main.go` - Cobra root command
- `cmd/login.go` - Authentication command
- `cmd/scan.go` - Source + audit submission with SSE streaming
- `cmd/status.go` - Audit status lookup
- `cmd/list.go` - Audit listing
- `cmd/memories.go` - Memory search and management
- `cmd/config.go` - Configuration management

### Shared Client (`backend/pkg/client/`)
- `client.go` - HTTP client with auth token injection
- `sse.go` - SSE stream reader for terminal output

### Config (`~/.vulture/config.json`)
```json
{
  "server_url": "http://localhost:8080",
  "token": "eyJhbG...",
  "default_types": ["chaos", "owasp", "soc2"],
  "output_format": "text"
}
```

## Terminal Output Format

### Scan Progress (SSE streaming)
```
Scanning /home/user/project...
[chaos] Starting Chaos Engineering audit...
[chaos] Checking retry patterns... found 3 issues
[owasp] Starting OWASP audit...
[owasp] Checking injection vulnerabilities... found 1 critical
[soc2]  Starting SOC2 audit (CC6, CC7)...

Results:
  CRITICAL  SQL Injection in auth/login.go:45
  HIGH      Missing circuit breaker in api/client.go:12
  MEDIUM    No retry policy for external calls in service/payment.go:88

Scores:
  Chaos: 72/100  OWASP: 45/100  SOC2: 81/100

Token savings: 67% (100 tokens saved from 5 cached findings)
```

### Status Output
```
Audit: abc-123
Status: completed
Duration: 5m 12s
Findings: 12 (3 critical, 4 high, 3 medium, 2 low)
Scores: chaos=72 owasp=45 soc2=81
```

## Token Caching Integration
- CLI scan automatically benefits from memory system
- Prior findings reduce token usage on re-scans
- Token savings displayed in CLI output
- `vulture memories search` enables finding lookup from terminal

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/charmbracelet/lipgloss` - Terminal styling
- `github.com/charmbracelet/bubbletea` - Interactive TUI (optional, for login prompts)

## Testing
- Go: Unit tests for each command (login, scan, status, list, memories, config)
- Go: Integration tests with mock HTTP server
- Go: E2E test: login -> scan -> status flow
