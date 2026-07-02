# Feature 0061 — Rollback Plan

## Blast radius

Four files in the shared agent library: `shared/cancellation.py` (new), `shared/transport/sse_app.py` (`/run` async rewrite + dedicated audit pool), `shared/audit_runner.py` (whole-audit deadline, skill-phase bounding, batch-loop checks, per-call timeout, L5 gating), `shared/validate/llm_judge.py` (L5 batch-loop token check). Plus config plumbing: `.env.example`, `docker-compose.yml` agent blocks (`${VAR:-default}`), CLAUDE.md. No Go backend, per-agent, frontend, or schema/migration changes. New runtime behavior: agents stop an audit (generate **and** L5 phases) when the SSE consumer disconnects, when the per-call timeout fires, or when the shared whole-audit wall-clock ceiling trips.

Highest-risk change is the transport rewrite (`sse_app.py` is shared by **all 10 agents**). A regression would surface immediately in the existing `test_transport.py` SSE tests (T6) + T12 — which gate the change.

## Instant mitigations (no code change)

- **Relax the per-call timeout:** raise `VULTURE_LLM_CALL_TIMEOUT_SEC` if legitimate calls are being cut.
- **Widen the audit ceiling:** raise `VULTURE_AGENT_MAX_AUDIT_SECONDS`; `0` disables it (⚠️ removes the hard termination guarantee — only for debugging).
- **Reduce/raise producer concurrency:** `VULTURE_AUDIT_EXECUTOR_WORKERS`.
- There is **no flag** to disable disconnect-cancellation itself (it is the fix). Full behavior revert = code revert below.

## Full revert (code)

1. `shared/audit_runner.py` — remove the whole-audit deadline, skill-phase `as_completed(timeout)` + `cancel_futures`, batch-loop token/deadline checks, the per-call `asyncio.wait_for`, and the `audit_cancelled` log. Restore the skill loop and batch loop to their 0059 form. Drop the three env reads.
2. `shared/transport/sse_app.py` — restore `POST /run` to the synchronous `def` returning `StreamingResponse(run_handler(...))`; remove `_cancellable_stream` and `_AUDIT_POOL`.
3. `shared/audit_runner.py` — remove the L5 gating (skip-if-cancelled, shared-budget cap, `ctx.run` thread wrap, bounded join).
4. `shared/validate/llm_judge.py` — remove the `current_cancel_token()` check from `run_l5`'s batch loop.
5. Config plumbing — remove the 3 vars from `.env.example`, the `${VAR:-default}` lines from `docker-compose.yml` agent blocks, and the CLAUDE.md entries.
6. Delete `shared/cancellation.py`.
7. Delete `agents/shared/tests/e2e/test_cancellation.py` and `agents/shared/tests/unit/test_cancellation.py`.

No dependency changes to undo (stdlib `contextvars`/`threading`/`asyncio`/`concurrent.futures` only).

## Consequence of reverting

Reverting **reinstates the orphaned-audit bug** (the `bdd9a5c1` behavior: unbounded post-timeout LLM sweeps) **and** the latent hung-call / hung-skill hang risks this feature also closes. Do not revert without an alternative mitigation. **0062 depends on this feature's `CancelToken`** — revert 0062 first.

## Verify after revert

- `agents/shared` suite green (minus the deleted cancellation tests).
- `/run` still streams SSE (`test_transport.py`).
- `grep -rn "CancelToken\|current_cancel_token\|VULTURE_AGENT_MAX_AUDIT_SECONDS\|VULTURE_LLM_CALL_TIMEOUT_SEC\|VULTURE_AUDIT_EXECUTOR_WORKERS\|_AUDIT_POOL" agents/shared` is empty.
