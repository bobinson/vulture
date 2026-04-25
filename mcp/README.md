# vulture-mcp

MCP server that exposes Vulture audit findings to AI coding assistants.

## Install

```bash
pip install vulture-mcp        # from PyPI (when published)
# or from source:
cd mcp && pip install -e .
```

## Quick start

```bash
# Start Vulture (any mode)
scripts/vulture.sh dev skills

# Test the MCP server
VULTURE_URL=http://localhost:28080 vulture-mcp
```

## Client configuration

### Claude Code

`~/.claude/mcp.json`:
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": {
        "VULTURE_URL": "http://localhost:28080"
      }
    }
  }
}
```

### Codex CLI

`.codex/mcp.json`:
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

### Cursor

Settings → MCP → Add Server:
```json
{
  "vulture": {
    "command": "vulture-mcp",
    "env": { "VULTURE_URL": "http://localhost:28080" }
  }
}
```

### Zed

`settings.json`:
```json
{
  "context_servers": {
    "vulture": {
      "command": { "path": "vulture-mcp" },
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "vulture": {
      "command": "vulture-mcp",
      "env": { "VULTURE_URL": "http://localhost:28080" }
    }
  }
}
```

### Continue

`~/.continue/config.yaml`:
```yaml
mcpServers:
  - name: vulture
    command: vulture-mcp
    env:
      VULTURE_URL: http://localhost:28080
```

### Remote (streamable-http)

```bash
VULTURE_URL=https://vulture.example.com \
VULTURE_API_KEY=vk_... \
VULTURE_MCP_TRANSPORT=streamable-http \
VULTURE_MCP_PORT=8100 \
vulture-mcp
```

## Tools

| Tool | Description | Writes? |
|------|-------------|---------|
| `vulture_list_audits` | Recent audit summaries | No |
| `vulture_get_findings` | Paginated findings with filters (severity, category, agent) | No |
| `vulture_get_finding_detail` | Single finding + lineage history | No |
| `vulture_get_comparison` | Diff vs previous audit (new/fixed/changed) | No |
| `vulture_search_findings` | Semantic search via pgvector | No |
| `vulture_list_lineage` | Lineage records with status filter | No |
| `vulture_update_status` | Triage: mark as false_positive, fixed, etc. | Yes (opt-in) |

## Environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `VULTURE_URL` | Yes | — | Vulture backend URL |
| `VULTURE_API_KEY` | No | — | API key (`vk_...`). Required if API keys enabled on backend. |
| `VULTURE_MCP_ALLOW_WRITE` | No | `false` | Enable `vulture_update_status` |
| `VULTURE_MCP_RATE_LIMIT` | No | `10` | Max requests/second to Vulture |
| `VULTURE_MCP_TRANSPORT` | No | `stdio` | `stdio` or `streamable-http` |
| `VULTURE_MCP_PORT` | No | `8100` | Port for streamable-http |

## Security

- API key held by MCP server — never in tool responses
- Code snippets and descriptions redacted: passwords, tokens, DSNs, API keys masked
- Writes disabled by default (`VULTURE_MCP_ALLOW_WRITE=false`)
- Rate limited (10 req/s, configurable)
- TLS enforced for streamable-http transport (http:// rejected unless localhost)
- httpx debug logging suppressed (prevents auth header leak to stderr)
- No eval, exec, pickle, subprocess, or file I/O
