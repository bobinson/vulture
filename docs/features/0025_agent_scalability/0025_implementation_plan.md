# 0025 Agent Scalability & Plug-and-Play Improvements

## Overview

Seven architecture improvements to reduce agent registration friction, eliminate dead code, normalize configuration, and add runtime health checking.

## Changes

| # | Change | Files |
|---|--------|-------|
| R7 | Remove dead `extractAgentConfig` | stream_service.go, stream_service_test.go |
| R6 | Fix `pattern_matcher.py` SKIP_DIRS | pattern_matcher.py |
| R5 | Remove `run_skill_audit` | audit_runner.py, test_audit_runner.py (unit+e2e) |
| R4 | Make LLM mode per-request | audit_runner.py, 6 agent.py files |
| R2 | Normalize config key to `categories` | soc2 config/clauses/agent, ssdf config/practice_groups/agent |
| R1 | Centralize agent registration | config.go, launcher.go, cli/main.go |
| R3 | Health-gated agent discovery | agent.go, agent_handler.go, agent_handler_test.go, types.ts |

## Adding a New Agent After These Changes

1. Append one `AgentRegistryEntry` to `AllAgents` in `config.go`
2. Create `agents/<name>/` from template
3. Add service block to `docker-compose.yml`
4. Frontend auto-discovers via `GET /api/agents`
