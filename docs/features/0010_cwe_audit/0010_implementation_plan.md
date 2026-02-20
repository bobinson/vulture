# 0010 CWE Audit - Implementation Plan

## Overview
Add a CWE (Common Weakness Enumeration) audit agent to Vulture, enabling automated detection of CWE-classified software weaknesses.

## Components

### 1. Python Agent (`agents/cwe/`)
- FastAPI microservice on port 8004
- Skills-based pattern matching for CWE categories (buffer overflow, injection, auth issues, crypto failures, resource management)
- Optional LLM phase via `run_combined_audit()`
- `SKILLS.md` documenting all CWE detection capabilities
- `/info` endpoint with `config_schema` for frontend auto-discovery

### 2. Backend Integration (`backend/internal/config/`)
- Register `cwe` agent in `defaultAgents()` with `VULTURE_AGENT_CWE_URL` env var
- Default URL: `http://agent-cwe:8004`

### 3. Docker Compose
- `agent-cwe` service block (port 8004, same pattern as other agents)
- Backend depends_on and environment variable for CWE agent URL

### 4. Frontend
- No changes required -- auto-discovered via `GET /api/agents`

## Execution Order
1. Create agent skeleton (agent.py, skills/, SKILLS.md, main.py, Dockerfile)
2. Implement CWE skills with pattern matching
3. Register in backend config
4. Add to docker-compose.yml
5. Write E2E tests
6. Verify all tests pass
