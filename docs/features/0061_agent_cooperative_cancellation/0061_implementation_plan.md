# Feature 0061 — Agent Cooperative Cancellation (stop orphaned audits)

| | |
|---|---|
| **Feature** | 0061_agent_cooperative_cancellation |
| **Status** | 📝 DRAFT v2 — hardened after chaos-engineering audit (see §11) |
| **Date** | 2026-07-01 |
| **Depends on** | 0057 (LLM-when-enabled bundle), 0059 (batch sweep loop `_collect_llm_findings_batched_async`). |
| **Prerequisite for** | 0062 (NATS coordination overlay) — the `CancelToken` introduced here is the object the NATS control plane later flips. |
| **Motivation** | Audit `bdd9a5c1` (source `/home/user/src/idattestor`) was marked `completed` at 14:21 UTC — **exactly 10:00 after start** (the backend's hard per-agent timeout). Yet ~2.5 h later the OWASP agent was **still** issuing chat completions to LM Studio (114 done, 5 queued, model at ~650 % CPU). The backend closes the HTTP connection on timeout, but the agent's synchronous audit generator never observes the disconnect and keeps sweeping the tree — an unbounded, orphaned LLM workload. |

## 1. Goal & the reliability guarantee

When the SSE consumer (the backend) goes away — timeout, user cancel, or any dropped connection — the agent must stop issuing new LLM calls promptly, release resources, and emit partial results cleanly.

**The hard guarantee is a wall-clock deadline, not disconnect detection.** Disconnect handling is the *fast path* (stops within one bounded operation of the client leaving); the wall-clock backstop is the *guaranteed ceiling* that holds even if disconnect detection silently fails (framework/ASGI edge cases, half-open TCP, buffering proxy). Cancellation is only ever as prompt as the **granularity of the bounded operations it sits between** — so this design also bounds those operations (F1, F2). The ceiling is a **single budget shared across BOTH LLM phases** — the generate sweep *and* the L5 validation/judge phase (F11) — not a per-phase timeout; otherwise the phases' timeouts stack and the "ceiling" is a fiction.

Non-goal: any messaging/bus machinery (0062). This is the minimal, self-contained cure for the runaway, hardened so it cannot be defeated by a single hung call or skill.

## 2. Root cause — two layers

**Layer 1 — the disconnect signal never reaches the work.** `shared/transport/sse_app.py` defines `POST /run` as a synchronous `def` returning a `StreamingResponse` over a **sync generator**. Starlette iterates sync generators in a threadpool thread; a Python thread cannot be interrupted, and nothing in the generator checks for cancellation. When the backend's `context.WithTimeout(ctx, 10*time.Minute)` (`backend/internal/service/agent_proxy_service.go:47`) closes the TCP connection, the thread runs on.

**Layer 2 — the work is a chain of uninterruptible blocking calls.** Phase 2 (`run_combined_audit → _collect_llm_findings → _collect_llm_findings_batched_async`) runs the entire batched sweep before returning; the batch loop (`~1547`) has no cancellation check. Worse, each individual operation is itself unbounded (§11 F1/F2): the LLM call has no timeout and skills have no timeout, so cancellation checks placed *between* operations can be starved indefinitely by a single stuck operation.

Fixing this requires three things: a signal (disconnect → token), cooperative checks between operations, **and** bounded operations so those checks are always reached.

## 3. Design

### 3.1 The cancellation primitive — ambient `CancelToken` via `contextvars`

New module `shared/cancellation.py`:

```python
import contextvars, threading

class CancelToken:
    """Cross-thread cooperative cancellation. Set from the async request
    context (disconnect); polled from the worker thread running the sync
    audit generator. threading.Event backing → safe cross-thread reads."""
    __slots__ = ("_event", "_reason")
    def __init__(self): self._event = threading.Event(); self._reason = None
    def cancel(self, reason="cancelled"):
        if not self._event.is_set(): self._reason = reason
        self._event.set()
    def cancelled(self): return self._event.is_set()
    @property
    def reason(self): return self._reason

_current: contextvars.ContextVar["CancelToken | None"] = \
    contextvars.ContextVar("vulture_cancel_token", default=None)
def set_cancel_token(tok): return _current.set(tok)
def current_cancel_token(): return _current.get()
```

**Why ambient (contextvar), not an explicit `cancel_token=` param:** all 10 agents wire through `create_sse_app`; an explicit param would force a (mostly dead) argument onto every handler, incl. `discover`/`prove`. Cancellation is a cross-cutting runtime concern (cf. Go `context.Context`), not an audit-config knob. Propagation through `copy_context().run → sync generator → asyncio.run → Task` was verified empirically (§3.4). Net: **4 files, zero agent edits** (`shared/cancellation.py`, `shared/transport/sse_app.py`, `shared/audit_runner.py`, and `shared/validate/llm_judge.py` for the L5 checkpoint — F11).

> **Critical propagation caveat (F11c):** `contextvars` are inherited by `asyncio` Tasks and copied by `copy_context()`, but a **raw `threading.Thread` starts with an empty context**. The L5 validation phase runs in exactly such a thread (`run_combined_audit`'s `_vthread`), so `current_cancel_token()` there returns `None` unless the thread target is explicitly wrapped: `Thread(target=lambda: ctx.run(_run_validate_in_thread))` using the same `ctx` that carries the token. Any future audit code that spawns its own threads must do the same or it will silently ignore cancellation.

> **Correction (F5):** the token is ambiently *available* to `discover`/`prove`, but they do not read it, so today they would **not** stop on disconnect (their sync gens keep running, exactly like the audit agents before this fix). This is acceptable only if their loops are bounded; verifying that and adding checkpoints to `discover`/`prove` if needed is a tracked follow-up (§7), **not** "free."

### 3.2 Transport — `shared/transport/sse_app.py` (single-producer-thread, F3/F4/F8)

`POST /run` becomes `async def`. It runs the **entire** sync `run_handler` generator in **one dedicated worker thread** (preserving today's single-thread execution model — no cross-thread generator resumption), inside a context that carries the token, and streams chunks to the async consumer over a thread-safe queue. The consumer's `finally` cancels the token.

```python
# dedicated, bounded pool for audit producers — NOT the default executor (F4)
_AUDIT_POOL = ThreadPoolExecutor(
    max_workers=_int_env("VULTURE_AUDIT_EXECUTOR_WORKERS", 8),
    thread_name_prefix="audit",
)

async def _cancellable_stream(run_handler, audit):
    cancel = CancelToken()
    ctx = contextvars.copy_context()
    ctx.run(set_cancel_token, cancel)                  # token bound ONCE, isolated to ctx
    loop = asyncio.get_running_loop()
    q: asyncio.Queue = asyncio.Queue()                 # UNBOUNDED — deliberate, see note below
    DONE = object()

    def _produce():
        try:
            for chunk in run_handler(audit.run_id, audit.source_path,
                                     audit.config, audit.prior_findings):
                loop.call_soon_threadsafe(q.put_nowait, chunk)
        except BaseException as e:                     # surface, don't swallow (F8)
            loop.call_soon_threadsafe(q.put_nowait, e)
        finally:
            loop.call_soon_threadsafe(q.put_nowait, DONE)

    fut = loop.run_in_executor(_AUDIT_POOL, ctx.run, _produce)
    try:
        while True:
            item = await q.get()
            if item is DONE: break
            if isinstance(item, BaseException): raise item
            yield item
    finally:
        cancel.cancel("stream_closed")   # disconnect → Starlette cancels this gen → finally runs
        # do NOT join the producer here; it observes the token at the next
        # bounded checkpoint and finishes on its own (≤ one bounded op).
```

Deliberate choices, each avoiding a real hazard:
- **Rely on Starlette's built-in disconnect cancellation; do NOT poll `request.is_disconnected()`** — that would create two consumers of the ASGI `receive` channel. Starlette cancels the body iterator on disconnect, raising `CancelledError` into `_cancellable_stream` → the `finally` sets the token.
- **One producer thread, context set once** (F3) — avoids resuming the generator across different threads and the async-generator-contextvar scoping quirk.
- **Dedicated bounded pool** (F4) — Phase-2 sweeps can't starve health checks / 0062 heartbeats. The (N+1)th concurrent audit **queues** on the pool rather than exhausting shared threads; `VULTURE_AUDIT_EXECUTOR_WORKERS` (default 8) is the documented per-agent concurrency cap.
- **The queue is UNBOUNDED, deliberately (R-3).** A *bounded* queue would deadlock the fix: if the consumer disconnects and stops draining, a full bounded queue blocks the producer inside `q.put`, so it would **never reach its next cancel checkpoint** — recreating the exact hang we are eliminating. Event volume is naturally bounded by findings/progress counts (hundreds), so unbounded memory is not a concern; the consumer (SSE `send`) is fast in the live path.
- **Producer exceptions are re-raised to the consumer** (F8) and surface as they do today; the token is still set in `finally`. No silent hang.
- **Never `.close()` a running generator** — only set the token; the producer unwinds itself.

### 3.3 Checkpoints + bounded operations — `shared/audit_runner.py`

**(a) Whole-audit deadline (F2/F6).** Compute a single deadline at the **start of `run_combined_audit`** (covers skills *and* LLM), from `VULTURE_AGENT_MAX_AUDIT_SECONDS` (default **900**, `0` disables). Read the ambient token once: `cancel = current_cancel_token()`.

**(b) Skill phase — bound + honor cancel (F2).**
- Consume with `as_completed(futures, timeout=remaining_deadline)`, catching `TimeoutError` to stop cleanly.
- Check `cancel`/deadline at the top of the loop.
- On cancel/timeout, `pool.shutdown(wait=False, cancel_futures=True)` — never block on a stuck skill. (Retain the existing `RuntimeError → wait=False` GC fallback.)

**(c) LLM batch loop — the critical site (`~1547`).** Check token **and** deadline before each call, reusing the `[partial results]` notice plumbing:

```python
for batch_idx, (batch_text, batch_paths) in enumerate(batches):
    if cancel and cancel.cancelled():
        notice = f"[partial results] audit cancelled ({cancel.reason}); stopped after {batch_idx}/{len(batches)} batch(es)."
        break
    if deadline and time.monotonic() > deadline:
        notice = f"[partial results] wall-clock cap reached; stopped after {batch_idx}/{len(batches)} batch(es)."
        break
    findings, error, in_tok, out_tok = await _bounded_call(batch_text, batch_paths)  # (d)
    ...
```

**(d) Per-LLM-call timeout (F1) — makes the guarantee sound.** Wrap each batch's `_collect_llm_findings_async` in `asyncio.wait_for(..., VULTURE_LLM_CALL_TIMEOUT_SEC)` (default **120**), so a hung/slow model cannot starve the between-batch checks. The wrapper (`_bounded_call`) **catches `asyncio.TimeoutError`** and returns a normal `(findings=[], error="llm call timed out", 0, 0)` tuple so the loop continues to its next cancel/deadline check — a timed-out call never propagates out as an unhandled exception. Because `wait_for` wraps the **whole** call (retries included), the worst-case stop latency after cancel ≤ `VULTURE_LLM_CALL_TIMEOUT_SEC` (R-1), not that × retries. Note (F7): `wait_for` injects `CancelledError` into `_collect_llm_findings_async`, which — being `BaseException` — escapes its `except Exception`, so **no cooldown/failure is recorded** for a cancel/timeout-driven interruption.

**(e) Circuit-breaker/fallback safety (F7).** Because we break **before** the next call, no spurious model failure is recorded on cancel. `CancelledError` is `BaseException` and already escapes `retry_llm_call`'s `except Exception`; the design **requires** keeping it off the retry/cooldown/fallback path so a cancel never trips a model cooldown or model fallback.

**(f) Observability (F10).** On cancel/backstop, emit a structured `logger.warning("audit_cancelled run_id=%s reason=%s batches=%d/%d")` in addition to the `[partial results]` notice, so ops (and 0062's tap) get a machine-readable signal.

**(g) L5 validation phase — the second LLM sweep (F11).** After generate, `run_combined_audit` runs the L5 judge in `_vthread`. Three changes make it obey the same guarantee:
- **Skip if already cancelled/expired** — before starting `_vthread`: `if (cancel and cancel.cancelled()) or (deadline and time.monotonic() > deadline): skip L5, go straight to result emission.`
- **Share the ceiling (F11a)** — cap L5's budget at the *remaining* whole-audit budget: `_vcfg.l5_total_timeout_s = min(configured, max(1, deadline - time.monotonic()))`. Now generate + L5 cannot exceed one shared ceiling.
- **Propagate the token into the thread + honor it (F11b/F11c)** — start the thread as `Thread(target=lambda: ctx.run(_run_validate_in_thread))` so the ambient token reaches L5; add a `current_cancel_token()` check to `run_l5`'s per-batch dispatch loop in `shared/validate/llm_judge.py` (which already checks its own `deadline` each batch — the token check sits right beside it), so a mid-L5 disconnect stops within one judge batch. L5's existing `shutdown(wait=False, cancel_futures=True)` already avoids blocking on in-flight workers.
- **Bounded join (F11b)** — `_vthread.join(timeout=remaining + grace)`; on timeout, proceed to result emission and let the daemon thread self-terminate via its now-shared deadline (never pin the generator/producer indefinitely).

### 3.4 Contextvar propagation (verified)

The token, set once via `ctx.run(set_cancel_token, cancel)`, is carried by `ctx` into the producer thread and — because `asyncio.run` inside Phase 2 copies the current context into its Task — into `_collect_llm_findings_batched_async`. Empirically confirmed the var set in the outer context is visible in the worker-thread sync body *and* the inner `asyncio.run` coroutine. Skill `ThreadPoolExecutor` workers don't need it (deterministic, no LLM).

## 4. Control surface

**Contract: every knob ships a safe default baked into the code and is overridable via `.env`** — no rebuild needed to tune. Defaults are applied by `_safe_int_env(name, default)` (unset/blank/invalid ⇒ default), so a missing `.env` entry always yields the documented default.

| Env var | Default | Meaning | Invariant |
|---|---|---|---|
| `VULTURE_AGENT_MAX_AUDIT_SECONDS` | `900` | Whole-audit wall-clock ceiling (skills+LLM). `0` disables. | **Must be ≥ backend per-agent timeout (600s)** so it only backstops, never truncates. `0` removes the only hard guarantee — discouraged in prod. |
| `VULTURE_LLM_CALL_TIMEOUT_SEC` | `120` | Per-LLM-call timeout (wraps the whole call incl. retries) so the batch loop always regains control. | > 0. Stop-latency after cancel ≤ this. |
| `VULTURE_AUDIT_EXECUTOR_WORKERS` | `8` | Dedicated audit-producer pool size = per-agent concurrent-audit cap. | ≥1. Excess concurrent audits queue. |
| `VULTURE_VALIDATE_LLM_TIMEOUT_MS` | `300000` | *(existing)* L5 total timeout. Phase 0 **caps its effective value at the remaining whole-audit budget** (F11a) so it can't stack on top of the ceiling. | — |

No config-schema / per-request knob — cancellation is runtime, not an audit option.

### 4.1 Configuration plumbing (so the knobs are actually settable)

A process env var is not operator-configurable until it is wired into both deployment paths (this repo does not auto-propagate to compose):

- **`.env.example`** — document all three new vars (commented defaults), mirroring the existing `VULTURE_LLM_CTX_SIZE` entry, so operators discover them.
- **Launcher / native / dev mode** — **no code change needed**: the launcher loads `.env` and spawns agents with `os.Environ()` as the base (`backend/internal/localdev/process.go:40`), so `.env` vars propagate to every agent automatically.
- **Docker-compose mode** — add each var to every agent `environment:` block using **`.env`-interpolation with a compose-level default**, e.g. `- VULTURE_AGENT_MAX_AUDIT_SECONDS=${VULTURE_AGENT_MAX_AUDIT_SECONDS:-900}`. This makes it overridable from `.env` *and* safe when unset (matches the code default). Precedent: `VULTURE_LLM_CTX_SIZE` is listed once per agent (11×). A conformance test in the spirit of `TestIssue10DockerCompose::test_ctx_size_in_all_agents` asserts the new vars are present in all agent blocks.
- **CLAUDE.md** — add the three vars to the Environment Variables section.

This plumbing is part of 0061's Definition of Done, not a follow-up.

## 5. Test plan (TDD, E2E-first, LLM-free, failure-injecting)

Written **before** implementation; they are the contract and are never edited to make code pass.

| # | Test | Asserts |
|---|---|---|
| T1 | Cancel before Phase 2 | token cancelled after skills ⇒ 0 LLM calls; skill findings + `result` still emitted. |
| T2 | Cancel mid-sweep | fake collector cancels the token on call #1 ⇒ **≤1 further** call, cancel notice emitted. |
| T3 | Wall-clock backstop | monkeypatch `time.monotonic` past the deadline ⇒ sweep stops with wall-clock notice (fast, no sleeping). |
| T4 | Transport disconnect → token | cancel the consuming task mid-stream ⇒ `finally` runs, `CancelToken` ends cancelled; producer exits. |
| T5 | `CancelToken` unit | `cancel/cancelled/reason`; contextvar isolation across contexts. |
| T6 | Existing transport green | `/run` still returns valid SSE + validates body after the async rewrite. |
| **T7** | **Hung LLM call (F1)** | a batch call that never returns ⇒ per-call timeout fires ⇒ loop regains control ⇒ cancel/deadline honored. |
| **T8** | **Hung skill (F2)** | a skill that blocks ⇒ whole-audit deadline + `as_completed(timeout)` + `cancel_futures` ⇒ audit ends, no hang. |
| **T9** | **Disconnect during skills** | token set before Phase 2 ⇒ Phase 2 skipped; partial result emitted. |
| **T10** | **Executor isolation (F4)** | `VULTURE_AUDIT_EXECUTOR_WORKERS` concurrent audits + one more ⇒ the extra queues; cancel of run A never affects run B. |
| **T11** | **Cancel ≠ cooldown (F7)** | cancelled/interrupted call ⇒ `cooldown_manager` records no failure; no model fallback triggered. |
| **T12** | **Generator exception (F8)** | run_handler raises ⇒ error surfaces to consumer, token set, no hang. |
| **T13** | **L5 honors cancel (F11b/F11c)** | cancel during the L5 phase ⇒ judge stops within one batch; `_vthread` joins promptly; token reaches L5 despite the raw-thread boundary (verifies the `ctx.run` wrap). |
| **T14** | **Shared ceiling (F11a)** | generate + L5 together never exceed `VULTURE_AGENT_MAX_AUDIT_SECONDS`; L5 pre-skipped when the budget is already spent. |

Placement: `agents/shared/tests/e2e/test_cancellation.py` (T1–T4, T7–T12) + `agents/shared/tests/unit/test_cancellation.py` (T5). Full `shared` suite (976+) re-run for regressions.

## 6. Acceptance criteria

- [ ] Disconnected/timed-out audit stops issuing LLM calls within one **bounded** op (≤1 in-flight) — T2, T4, T7.
- [ ] Cancel-before-LLM skips Phase 2 — T1, T9.
- [ ] No single hung call **or** hung skill can prevent termination — T7, T8.
- [ ] Whole-audit wall-clock ceiling always terminates and **spans generate + L5 as one shared budget** — T3, T14.
- [ ] L5 validation honors cancel (stops within one judge batch; token crosses the raw-thread boundary) — T13.
- [ ] Cancel never trips model cooldown/fallback — T11.
- [ ] Audit producers isolated from shared executor; concurrent runs isolated — T10.
- [ ] Zero agent-file changes; existing SSE behavior preserved — T6, T12.
- [ ] Full `shared` + per-agent suites green.

## 7. Scope-lock — explicitly OUT / deferred

- **NATS / any bus** — 0062.
- **User-facing cancel button / backend cancel endpoint** — 0062 (publish-cancel). Phase 0 handles the timeout/disconnect trigger only.
- **Changing the backend 10-min timeout** — unchanged; this makes the agent *react*.
- **Interrupting a truly in-flight single LLM call** — not cooperatively possible; ≤1 in-flight (bounded by the per-call timeout) is the accepted floor.
- **`discover`/`prove` checkpoints (F5)** — tracked follow-up; verify their loops are bounded, add checkpoints if not.

## 8. Operational note

The fix takes effect only after agents restart (they load `sse_app.py`/`audit_runner.py`). Restarting also clears any currently-orphaned sweep — so the deploy doubles as remediation for the live `bdd9a5c1` runaway.

## 9. Blast radius (chaos)

- **The fix itself** touches `sse_app.py` — shared by all 10 agents; a regression breaks the whole fleet's `/run`. Mitigation: the existing transport tests (T6) gate the change; it is small and revertible (0061 rollback). There is no runtime toggle for the transport rewrite — the mitigation is test coverage + fast revert.
- **Failure to cancel** (hung call/skill) is bounded by the per-call timeout (F1) and whole-audit deadline (F2/F6): worst case ≈ 900s of orphaned compute, vs. today's unbounded hours.
- **Memory**: producer→consumer queue is bounded by per-audit event count (findings/progress — hundreds), not by codebase size.
- **Executor**: dedicated bounded pool (F4) — over-concurrency queues rather than starving health/heartbeat work.

## 10. Reliability summary (chaos skills)

| Skill | How addressed |
|---|---|
| **Timeout** | per-LLM-call timeout (F1) + whole-audit wall-clock ceiling (F2/F6) + skill `as_completed(timeout)`. |
| **Fallback** | on cancel, degrade to partial results + `result`/`run_finished`; disconnect fast-path degrades to the wall-clock guarantee. |
| **Circuit-breaker** | cancel breaks before the next call; `CancelledError` kept off retry/cooldown/fallback (F7). |
| **Retry** | existing `retry_llm_call` retained; each attempt now bounded (F1) so retries can't run unbounded. |
| **Blast-radius** | §9 — bounded compute, bounded memory, isolated executor, fleet-wide change gated by tests. |

## 11. Audit trail — chaos-engineering review (2026-07-01)

Findings F1–F10 (see the review that produced this v2) incorporated: F1 per-call timeout (§3.3d, §4), F2 skill-phase bounding + whole-audit deadline (§3.3a-b), F3 single-producer-thread transport (§3.2), F4 dedicated executor (§3.2, §4), F5 corrected `discover`/`prove` claim (§3.1, §7), F6 reframed backstop as the guarantee + invariants (§1, §4), F7 cooldown/fallback safety (§3.3e), F8 exception surfacing (§3.2), F9 chaos tests T7–T12 (§5), F10 structured cancel signal (§3.3f).

**Re-audit pass (same session)** caught three issues in the v2 fixes themselves: R-1 stop-latency is ≤ the per-call timeout total, not ×retries (§3.3d, §4); R-2 the timeout wrapper must catch `TimeoutError` → error tuple and keep `CancelledError` off the cooldown path (§3.3d); R-3 the producer→consumer queue must be **unbounded** or a disconnected consumer deadlocks the producer before it can observe cancel (§3.2). All three folded in.

**Second audit pass (v3, fresh code-path review).** F11 — the **L5 validation/judge is a second LLM-call phase** (`run_combined_audit:1287`) my design had ignored. It is internally bounded (300s total / 30s batch / per-call timeouts, non-blocking shutdown) so not infinite, but had **zero cancel awareness**, yielding: F11a a broken whole-audit ceiling (L5's 300s is additive → real ceiling was 1200s); F11b up to 300s of post-disconnect judge spend; F11c the ambient token does **not** reach L5's raw `threading.Thread` (contextvars aren't inherited by manual threads). Fixed in §1 (shared ceiling), §3.1 (raw-thread caveat), §3.3g (skip-if-cancelled, shared budget cap, `ctx.run` thread wrap + `run_l5` batch-loop token check, bounded join), §4/§4.1 (config + plumbing). **Closure:** generate + L5 are the only two LLM-call paths in an agent audit; both are now bounded and cancel-aware. No further LLM-runaway paths exist — audit converged.

**Config-plumbing note (from review):** every knob ships a code default and is `.env`-overridable in both launcher (auto via `os.Environ()`) and compose (`${VAR:-default}` interpolation) modes — §4/§4.1; part of DoD, not a follow-up.

**Post-implementation adversarial verification (2026-07-02, 28-agent workflow).** 6-lens parallel review → per-finding verify; 21 CONFIRMED. Material fixes applied: (a) the F7/F11a/F11b/F11c tests were structural `inspect.getsource` theater — replaced with behavioral tests; (b) an in-flight L5 batch could issue its strict-JSON retry after cancel — `_call_with_strict_retry` now takes the token (pool workers don't inherit contextvars) and skips it; (c) `VULTURE_LLM_CALL_TIMEOUT_SEC≤0` floored. Remaining findings are accepted, documented trade-offs (see `0061_implementation_status.md`): between-op cancel granularity, the dedicated-pool concurrency ceiling, the wall-clock cap vs long happy-path audits, the deliberately-unbounded queue, and hung-skill atexit lingering.
