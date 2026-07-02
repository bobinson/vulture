# Feature 0062 — NATS Coordination Overlay (control · lifecycle · observability)

| | |
|---|---|
| **Feature** | 0062_nats_coordination_overlay |
| **Status** | 📝 DRAFT — for review (nothing implemented) |
| **Date** | 2026-07-01 |
| **Depends on** | **0061** (Phase 0 — agent cooperative cancellation — `CancelToken` + contextvar + transport wiring + batch-loop checkpoints in `audit_runner.py`). 0057 (LLM-when-enabled bundle), 0059 (Tier‑3 / batch sweep loop where the cancel checkpoint lives). |
| **Motivation** | A completed audit (`bdd9a5c1`) left agents issuing LLM requests to LM Studio for **~2.5 h after** the backend marked it done: the backend's 10‑min per-agent timeout (`agent_proxy_service.go:47`) closes the HTTP connection, but the agents' synchronous audit generators never observe the disconnect and keep sweeping the tree. Phase 0 fixes the immediate leak via cooperative cancellation. This feature makes coordination **first-class and reliable**: cancel becomes a published message (not a best-effort TCP close), agents gain live presence/lifecycle, and the whole system gets a single observability tap — without adding a hard infrastructure dependency. |

## 1. Goal & guiding principle

Add a lightweight **message bus alongside** the existing HTTP/SSE audit path — never replacing it — providing three capabilities the fleet lacks:

1. **Control plane** — reliable, multi-agent-atomic cancel (and future pause/resume).
2. **Lifecycle / presence** — agents announce `starting → ready → busy → draining → stopping` + heartbeats.
3. **Observability tap** — one subscription (`vulture.>`) sees everything.

**Guiding principle — NATS is an enhancement layer, never a correctness dependency.**

- Flag **off** → byte-identical to today (HTTP/SSE + Phase 0 disconnect-cancellation).
- Flag **on**, broker **reachable** → control/lifecycle/observability ride NATS.
- Flag **on**, broker **unreachable** → audits still run; cancellation degrades to the Phase 0 disconnect path; **no audit ever fails because NATS is down.**

## 2. Background — why the overlay (and why not more)

Current architecture: Go backend orchestrator → HTTP `POST /run` → Python FastAPI agents that stream SSE back; the backend aggregates and re-emits SSE to the frontend. Agents are independent processes with **no channel between them** and **no control channel from the backend** other than the HTTP request lifecycle. Cancellation today is implicit: the backend's context timeout closes the TCP connection and *hopes* the agent stops (Phase 0 makes that hope real, but still couples "stop" to "socket dropped").

The overlay decouples **control** and **telemetry** from the HTTP request lifecycle. It deliberately does **not** move the primary audit event/result transport onto NATS, nor introduce inter-agent collaboration — those are larger, separately-specified steps (see §9 Scope-lock).

## 3. Requirements

| # | Requirement |
|---|---|
| R1 | Backend embeds an in-process `nats-server` (default) and connects a `nats.go` client; external broker via `VULTURE_NATS_URL` for HA. |
| R2 | `VULTURE_NATS_ENABLED` (default **false**). Off ⇒ no connection attempted, zero behavior change. |
| R3 | On per-agent timeout **or** user cancel, backend publishes one `cancel` on `vulture.audit.<run_id>.control`; every agent working that run stops. |
| R4 | Agents subscribe per-run on `/run`; a `cancel` message flips the **same Phase 0 `CancelToken`** the audit generator already polls. No new code in the batch loop. |
| R5 | Agents publish presence (`ready` on startup, `busy`/`draining` transitions) + periodic heartbeat; backend keeps a live agent view. |
| R6 | Broker unreachable while enabled ⇒ warn + continue; cancellation falls back to Phase 0 disconnect. Never crash, never block startup. |
| R7 | Core NATS pub/sub only — **no JetStream** required for this feature. |
| R8 | Works across all five deployment modes (§7) with no new mandatory infra in Modes A/E. |

## 4. Low-level design

### 4.1 Subject taxonomy

| Subject | Direction | Payload (JSON) |
|---|---|---|
| `vulture.audit.<run_id>.control` | backend → agents | `{cmd: "cancel"\|"pause"\|"resume", reason, ts}` |
| `vulture.agent.<type>.presence` | agents → all | `{agent, pid, status, active_runs, ts}` |
| `vulture.agent.<type>.heartbeat` | agents → all | `{agent, ts, active_runs}` |
| `vulture.audit.<run_id>.event.<agent>` | agents → backend | *(deferred — see decision D1)* mirror of AgUI events |
| `vulture.>` | any subscriber | observability tap |

Subjects are hierarchical so a single `vulture.>` (or `vulture.agent.>`) wildcard taps the class of traffic without per-subject wiring.

### 4.2 Agent side (Python — `nats-py`, inside the existing uvicorn asyncio loop)

**Connection lifecycle** (FastAPI lifespan in `shared/transport/sse_app.py`):

```python
# pseudocode — shared/transport/nats_client.py (new), wired into create_sse_app's lifespan
async def startup():
    if not nats_enabled():            # VULTURE_NATS_ENABLED
        return
    try:
        nc = await nats.connect(nats_url(), max_reconnect_attempts=-1, ...)
    except Exception as e:
        log.warning("nats connect failed (%s) — degrading to disconnect-cancel", e)
        return                        # R6: never block startup
    await publish_presence(agent, "ready")
    start_heartbeat_task(agent)       # periodic vulture.agent.<type>.heartbeat
```

**Per-run control subscription + registry** — the integration seam with Phase 0:

```python
# in the /run handler path (transport), when an audit starts:
cancel = CancelToken()                # Phase 0 primitive
set_cancel_token(cancel)              # Phase 0 contextvar (unchanged)
_RUN_REGISTRY[run_id] = cancel        # NEW: {run_id -> CancelToken}, guarded by a lock
sub = await nc.subscribe(f"vulture.audit.{run_id}.control", cb=_on_control)
# ...
async def _on_control(msg):
    if json.loads(msg.data).get("cmd") == "cancel":
        tok = _RUN_REGISTRY.get(run_id)
        if tok: tok.cancel("nats_control")     # flips the SAME token the batch loop polls
# finally (run ends / stream closes):
await sub.unsubscribe(); _RUN_REGISTRY.pop(run_id, None)
```

Because the token flipped here is the exact object `run_combined_audit` polls (Phase 0), **a NATS-triggered cancel traverses the identical path as a disconnect-triggered one** — `audit_runner.py`'s batch loop needs no change beyond Phase 0. The registry (`dict` + `threading.Lock`) is the only new agent state.

### 4.3 Backend side (Go — embedded server + `nats.go` client)

- **Embedded server** (`internal/bus/`, new): `server.NewServer(&server.Options{...})` on a loopback host/port (or unix socket), started in `server.go` startup **behind the flag**, stopped on shutdown. External URL bypasses embedding.
- **Client**: publishes `cancel`; subscribes `vulture.agent.>` for the live-agent view and (optionally, D1) `vulture.audit.*.event.*` for the observability mirror.
- **Cancel triggers**:
  - *Timeout*: at the `context.WithTimeout(ctx, 10*time.Minute)` site (`agent_proxy_service.go:47`), on `ctx.Done()` publish `cancel` for the run before/besides closing the HTTP stream.
  - *User cancel* (decision D3): `DELETE /api/audits/{id}` → mark audit `cancelled` → publish `cancel`. One publish stops the whole fleet atomically (vs. today's per-connection teardown).

### 4.4 Order of operations (cancel, flag on)

```
backend timeout / user DELETE
      │  publish vulture.audit.<run_id>.control {cmd:"cancel"}
      ▼
each agent on that run: _on_control → registry[run_id].cancel("nats_control")
      ▼
audit_runner batch loop (Phase 0 checkpoint): cancel.cancelled() → break, emit [partial results]
      ▼  ≤1 in-flight LLM call completes; no new calls issued
run ends; agent unsubscribes + deregisters
```

## 5. Deployment matrix

| Mode | NATS behavior |
|---|---|
| A dev-local | Embedded in backend; agents connect over loopback. No `docker-compose` change required. |
| B centralized | Embedded, or set `VULTURE_NATS_URL` to an external/HA broker for all services. |
| C readonly viewer | Subscriber-only (observability); never publishes control. |
| D CI client | Unaffected — CLI talks HTTP to the server. |
| E native (no Docker) | Embedded server in the single binary — the reason we embed rather than sidecar. |

## 6. Configuration surface

| Env var | Default | Meaning |
|---|---|---|
| `VULTURE_NATS_ENABLED` | `false` | Master switch. Off ⇒ no connection, no behavior change. |
| `VULTURE_NATS_URL` | *(unset)* | Unset ⇒ embedded/loopback; set ⇒ external broker. |
| `VULTURE_NATS_HEARTBEAT_SEC` | `10` | Agent heartbeat interval. |

## 7. Test plan (TDD, E2E-first, broker-in-process, LLM-free)

Tests use an embedded/ephemeral NATS instance and fake skills; **no live LLM, no live model**.

| # | Test | Asserts |
|---|---|---|
| T1 | **Cancel-over-NATS** (core contract) | enabled + publish `control.cancel` for a run ⇒ the audit's LLM sweep stops within one batch (≤1 in-flight), `[partial results]` notice emitted. Builds on Phase 0's cancel test. |
| T2 | **Degradation** | enabled + broker down ⇒ audit completes; cancellation falls back to disconnect; no crash; startup not blocked. |
| T3 | **Flag-off parity** | `VULTURE_NATS_ENABLED=false` ⇒ no connection attempted; behavior identical to today. |
| T4 | **Lifecycle** | agent publishes `ready` on startup; backend live-view reflects it; missed heartbeats ⇒ marked stale. |
| T5 | **Registry hygiene** | `{run_id → CancelToken}` entry added on `/run`, removed on completion/disconnect; concurrent runs isolated (cancel of run A never touches run B). |
| T6 | **Go embedded server** | starts/stops with backend lifecycle behind the flag; client publish/subscribe round-trip; external-URL path skips embedding. |
| T7 | **Multi-agent atomic cancel** | one `cancel` publish stops all agents subscribed to that run. |

Per project workflow: E2E business-logic tests written **first**; implementation makes them pass; full agent + backend suites re-run after every change. E2E tests are the contract and are never edited to make code pass.

## 8. Acceptance criteria

- [ ] Flag off ⇒ zero behavior change (T3).
- [ ] Flag on + reachable ⇒ published `cancel` stops the fleet within one batch, atomically (T1, T7).
- [ ] Flag on + unreachable ⇒ audits run, cancel degrades to Phase 0, no crash (T2).
- [ ] Live agent view driven by presence/heartbeat (T4).
- [ ] Registry has no leaks across concurrent/repeated runs (T5).
- [ ] All five deployment modes documented and smoke-tested where applicable.

## 9. Scope-lock — explicitly OUT (separate specs)

- **Collaboration fabric** — agents feeding each other findings / a shared per-run blackboard and coordinator-side live dedup. *Phase 2.*
- **Replacing HTTP/SSE** as the primary audit request/result transport. The overlay is additive.
- **JetStream** persistence / durable SSE replay. Core pub/sub only here.
- **Peer-to-peer dedup.** Dedup stays authoritative at the aggregation point (backend / memory layer); the bus shares context, it does not arbitrate truth.

## 10. Open decisions (for review — current draft picks marked ★)

- **D1 — event mirroring:** ★ control + lifecycle only now; mirror AgUI events to NATS as a fast-follow. (Alt: mirror everything immediately — richer tap, more traffic.)
- **D2 — embedded vs external:** ★ embedded-by-default (keeps Modes A/E zero-infra); external via URL.
- **D3 — user-facing cancel:** ★ include the backend `DELETE /api/audits/{id}` → publish-cancel path in 0062; frontend "Cancel" button tracked as a small separate follow-up.
- **D4 — feature name:** ★ `0062_nats_coordination_overlay`.
