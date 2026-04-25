# 0032 Vulture MCP Server — Rollback Plan

## Strategy

The MCP server is a standalone subdirectory (`mcp/`) with zero imports from the backend. Rollback = delete the directory.

```bash
rm -rf mcp/
git add -A && git commit -m "revert: remove vulture-mcp (0032)"
```

## Impact

- No backend code touched — zero runtime impact on Vulture itself.
- No database migrations — the MCP is a read-only API client.
- No Docker changes — the MCP runs as a local process, not a container.
- Agent harnesses that had `vulture` in their MCP config will fail to start it — they degrade gracefully (tool unavailable).

## Partial rollback

Not applicable — the feature is a single self-contained directory.
