# 0009 - Prove Companion Agents Implementation Plan

## Overview

Add a prove companion agent that autonomously verifies scanner findings against a staging environment using Plan-Review-Execute loops.

## Architecture

Single unified prove agent service with strategy modules per scanner type:

```
CLI: vulture prove /path --staging-url https://staging.example.com --types owasp,chaos
  → Backend: POST /api/prove → creates prove session → dispatches to prove agent
  → Prove Agent (port 28005):
      1. Fetch scanner findings from backend cache or prior_findings
      2. For each finding → strategy.plan() → strategy.review() → strategy.execute()
      3. Stream SSE events: proof_plan, proof_review, proof_attempt, proof_result
  → Backend: Persists proof results alongside original findings
```

## Components

### 1. Python Prove Agent (`agents/prove/`)
- FastAPI service using `create_sse_app` pattern
- `run_prove()` generator orchestrates the pipeline
- `runner.py` implements Plan-Review-Execute loop per finding
- Strategy modules: `owasp.py`, `chaos.py`, `soc2.py`, `cwe.py`
- LLM required (no skill-only mode)

### 2. SSE Events
- `proof_plan`: Verification plan for a finding
- `proof_review`: Safety review result
- `proof_attempt`: Execution attempt result
- `proof_result`: Final verdict per finding
- `proof_summary`: Overall summary

### 3. Backend Integration
- Agent registered in `config.go`
- Event constants in `model/event.go`
- Event translation in `agui/translator.go`
- Local dev launcher in `localdev/launcher.go`

### 4. CLI `vulture prove`
- `--staging-url` (required)
- `--types` (default: all)
- `--max-iterations` (default: 3, max: 10)
- `--allow-local` (default: false)

### 5. Safety Mechanisms
- Staging URL validation (blocks localhost by default)
- LLM safety review before each execution
- Iteration limit (max 10)
- HTTP-only verification
- 10s request timeout
- Circuit breaker (3 consecutive failures)

## Files Created
- `agents/prove/` — Full agent package
- `docs/features/0009_prove_agents/` — Documentation

## Files Modified
- `agents/shared/shared/transport/event_emitter.py` — 5 proof event methods
- `backend/internal/config/config.go` — Prove agent registry
- `backend/internal/model/event.go` — Proof event constants
- `backend/internal/agui/translator.go` — Proof event translators
- `backend/internal/localdev/launcher.go` — Prove agent startup
- `cli/main.go` — `vulture prove` command
- `docker-compose.yml` — Prove service block
- `Makefile` — Prove test target
