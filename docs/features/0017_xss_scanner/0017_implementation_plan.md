# 0017 — XSS Scanner Agent Implementation Plan

## Overview

Standalone XSS scanner agent with 5 focused skills covering all cross-site scripting vectors: reflected XSS, stored XSS, DOM-based XSS, template injection (SSTI), and header injection with missing security headers.

## Architecture

- New agent at `agents/xss/` following the established CWE/OWASP pattern
- Registered as type `"xss"` on port 28006
- Uses `run_combined_audit()` for two-phase pipeline (skills + optional LLM)
- Frontend auto-discovers via `GET /api/agents`

## Skills

| Skill | CWE | Description |
|-------|-----|-------------|
| `reflected_xss_check` | CWE-79 | User input reflected in HTTP responses without encoding |
| `stored_xss_check` | CWE-79 | Database/store reads rendered unsafely |
| `dom_xss_check` | CWE-79 | JavaScript source-to-sink data flows |
| `template_injection_check` | CWE-1336 | SSTI leading to XSS or RCE |
| `header_injection_check` | CWE-113/644 | Header injection + missing security headers |

## Files Created

- `agents/xss/pyproject.toml` — Package configuration
- `agents/xss/Dockerfile` — Container build (port 28006)
- `agents/xss/xss_agent/__init__.py` — Package marker
- `agents/xss/xss_agent/config.py` — Agent info, categories, config schema
- `agents/xss/xss_agent/agent.py` — run_audit() entry point
- `agents/xss/xss_agent/main.py` — FastAPI app via create_sse_app()
- `agents/xss/xss_agent/skills/__init__.py` — SKILL_MAP + SKILL_TOOLS exports
- `agents/xss/xss_agent/skills/SKILLS.md` — Skill documentation
- `agents/xss/xss_agent/skills/reflected_xss_check.py`
- `agents/xss/xss_agent/skills/stored_xss_check.py`
- `agents/xss/xss_agent/skills/dom_xss_check.py`
- `agents/xss/xss_agent/skills/template_injection_check.py`
- `agents/xss/xss_agent/skills/header_injection_check.py`
- `agents/xss/tests/unit/test_skills.py` — Unit tests

## Files Modified

- `backend/internal/config/config.go` — Added xss agent entry
- `backend/internal/localdev/launcher.go` — Added xss to AgentPorts, agents list, backend env
- `docker-compose.yml` — Added agent-xss service block + backend dependency
- `frontend/src/i18n/locales/{en,es,de,fr,ja,pt}.json` — Added agents.xss + audit.xssDesc

## Two-Phase Pipeline

**Phase 1 (Skills)**: 5 skills run concurrently via ThreadPoolExecutor. Deterministic regex + context-aware safe exclusions. 100% file coverage.

**Phase 2 (LLM, when enabled)**: XSS-specific system instructions guide LLM to trace data flows, identify sanitization bypasses. Deduplicates against Phase 1 findings.

## Prove Agent Compatibility

No prove agent changes needed. XSS findings carry all required fields for prove verification.
