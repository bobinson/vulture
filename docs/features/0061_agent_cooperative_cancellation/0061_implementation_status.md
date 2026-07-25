# Feature 0061 — Implementation Status

| | |
|---|---|
| **Status** | 🟢 IMPLEMENTED (v3) — full fleet green; under adversarial verification |
| **Date** | 2026-07-02 |
| **Prerequisite for** | 0062 (NATS coordination overlay) |
| **Branch** | `feature/0061-agent-cooperative-cancellation` |

## Verification (2026-07-02)
- Full `shared` suite: **1005 passed**.
- Per-agent suites all green: chaos 34 · owasp 112 · soc2 36 · cwe 632(+1 skip) · xss 96 · ssdf 61 · asvs 114 · do178c 64 · discover 395 · prove 315.
- New 0061 tests: **28 passed** (behavioral T1–T14 + F11c thread-propagation + config conformance).

## Adversarial verification round (28-agent workflow, 2026-07-02)
Ran a 6-lens parallel review → per-finding adversarial verify. 21 findings CONFIRMED; triaged:

**Fixed:**
- 3× HIGH — T11/T13/T14 were `inspect.getsource` string-matching (theater). Replaced with **behavioral** tests: F7 (`wait_for` cancel skips the `except Exception`/cooldown block), F11c (token crosses a raw-thread boundary via `copy_context().run`; a bare thread does not), F11b (real `run_l5` pool loop stops mid-sweep on cancel), F11a (real `run_l5` produces verdicts with no ceiling, none once the ambient deadline is past).
- MEDIUM #4 — an in-flight L5 batch could still issue its strict-JSON **retry** after cancel; now `_call_with_strict_retry` takes the token (passed, not ambient — pool workers don't inherit contextvars) and skips the retry when cancelled. New behavioral test `test_t13d`.
- NIT #21 — `VULTURE_LLM_CALL_TIMEOUT_SEC` ≤0 would make `wait_for` insta-timeout every call; now floored to the default.
- T2 strengthened to assert it stops after exactly 1 batch (`acc == []`, "after 1 of 5").

**Accepted trade-offs (documented, not defects):**
- Cancel is polled *between* bounded ops: an in-flight generate call runs to `VULTURE_LLM_CALL_TIMEOUT_SEC` (≤1 in-flight); in-flight L5 batches to `per_batch_timeout` (≤concurrency). This *is* the design's stated bound.
- Dedicated 8-worker `_AUDIT_POOL` (vs Starlette's ~40): the 9th concurrent `/run` per agent queues. By design (F4); tune `VULTURE_AUDIT_EXECUTOR_WORKERS`.
- Whole-audit wall-clock cap can shorten a legitimately long audit on the happy path — but 900s > the backend's 600s per-agent timeout, so the backend already abandons earlier; configurable / `0` disables.
- Unbounded producer→consumer queue can grow for a *slow-but-connected* consumer (bounded by event count) — deliberate to avoid the disconnect deadlock (R-3).
- A *truly* hung (never-returning) skill leaves a non-daemon pool thread that can delay interpreter shutdown at atexit; the audit itself still terminates by the deadline.
- T4 simulates disconnect via `aclose()` (not full ASGI) and T10 asserts pool config (not live N+1 queueing) — accepted proxies.

## Design — ✅ COMPLETE (v3, chaos-audited ×2)
- Root cause pinned (two layers + unbounded per-op operations).
- Ambient `CancelToken` (contextvar); propagation verified empirically.
- Chaos audit F1–F10 incorporated (plan §11): per-call timeout, whole-audit deadline, single-producer-thread transport, dedicated executor, cooldown-safety, chaos tests.
- **Second audit F11**: L5 validation is the 2nd LLM phase — added skip-if-cancelled, shared whole-audit budget cap, raw-thread `ctx.run` token propagation, `run_l5` batch-loop token check, bounded join. Both LLM paths (generate + L5) now covered.
- **Config**: all knobs = code default + `.env`-overridable (launcher auto; compose `${VAR:-default}`).
- **Scope**: now **4 files** (adds `shared/validate/llm_judge.py`).

## Part A — `shared/cancellation.py` (new) — ✅ DONE
- [ ] `CancelToken` (threading.Event + reason) + `set_cancel_token` / `current_cancel_token`.

## Part B — Transport (`shared/transport/sse_app.py`) — ✅ DONE
- [ ] `/run` → `async def`; single-producer-thread `_cancellable_stream` (whole gen in one dedicated-pool thread, context set once, queue to consumer).
- [ ] Dedicated `_AUDIT_POOL` (`VULTURE_AUDIT_EXECUTOR_WORKERS`, default 8).
- [ ] Cancel token in `finally`; producer exceptions re-raised; rely on Starlette disconnect (no `is_disconnected()`, no `gen.close()`).

## Part C — Checkpoints + bounded ops (`shared/audit_runner.py`) — ✅ DONE
- [ ] Whole-audit deadline at `run_combined_audit` start (`VULTURE_AGENT_MAX_AUDIT_SECONDS`, default 900).
- [ ] Skill phase: `as_completed(timeout=…)` + token check + `shutdown(wait=False, cancel_futures=True)`.
- [ ] LLM batch loop: token + deadline check before each call.
- [ ] Per-LLM-call timeout `asyncio.wait_for` (`VULTURE_LLM_CALL_TIMEOUT_SEC`, default 120).
- [ ] Cooldown/fallback safety: cancel breaks before next call; `CancelledError` kept off retry/cooldown path.
- [ ] Structured `audit_cancelled` log on cancel/backstop.

## Part D — L5 validation cancellation (`audit_runner.py` + `shared/validate/llm_judge.py`) — ✅ DONE
- [ ] Skip L5 if cancelled/past deadline before starting `_vthread`.
- [ ] Cap `l5_total_timeout_s` at remaining whole-audit budget (shared ceiling).
- [ ] Wrap `_vthread` target in `ctx.run` so the token crosses the raw-thread boundary.
- [ ] `run_l5` batch loop checks `current_cancel_token()` beside its existing deadline check.
- [ ] `_vthread.join(timeout=…)`; proceed on timeout.

## Part E — Config plumbing — ✅ DONE
- [ ] `.env.example` entries for the 3 new vars (commented defaults).
- [ ] docker-compose per-agent `${VAR:-default}` for all agent blocks + conformance test.
- [ ] CLAUDE.md Environment Variables section updated.
- [ ] Launcher: no change (auto-inherits via `os.Environ()`).

## Tests (E2E-first) — ✅ DONE
- [ ] T1–T6 (core) + **T7 hung-call · T8 hung-skill · T9 disconnect-during-skills · T10 executor isolation · T11 cancel≠cooldown · T12 generator-exception · T13 L5-honors-cancel · T14 shared-ceiling**.
- [ ] Full `shared` suite (976+) regression pass.

## Verification (to record on completion)
- [ ] Manual: start an audit, drop client / force timeout ⇒ agent stops within one bounded op (watch LM Studio queue drain).
- [ ] Manual: hung-model + hung-skill fault injection ⇒ audit still terminates by the deadline.

## Not done / follow-ups
- Restart agents to load the fix (also clears the live `bdd9a5c1` orphan).
- **F5**: verify `discover`/`prove` loops are bounded; add checkpoints if not.
- 0062 builds on this token.
