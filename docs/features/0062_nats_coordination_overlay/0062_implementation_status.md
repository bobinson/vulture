# Feature 0062 — Implementation Status

| | |
|---|---|
| **Status** | 📝 DRAFT — design under review; **nothing implemented** |
| **Date** | 2026-07-01 |
| **Prerequisite** | 0061 (Phase 0 — agent cooperative cancellation) must land first — provides the `CancelToken` this feature flips. |

## Prerequisite — Phase 0 (agent cooperative cancellation) — ⏳ STAGED (not yet committed)

Designed and ready to implement (3 files, zero agent edits):
- `shared/cancellation.py` (new) — `CancelToken` (threading.Event-backed) + `contextvars` accessor.
- `shared/transport/sse_app.py` — `/run` → async; bind token into context; drive sync handler via `asyncio.to_thread`; cancel token in `finally` (Starlette raises `CancelledError` into the generator on client disconnect).
- `shared/audit_runner.py` — `run_combined_audit` reads ambient token, curtails Phase 2; batch loop (line 1547) checks token + wall-clock backstop (`VULTURE_AGENT_MAX_AUDIT_SECONDS`, default 900s).

Contextvar propagation through `asyncio.to_thread → asyncio.run → Task` verified empirically.

## Part A — Backend embedded bus + client — ⬜ NOT STARTED
- [ ] `internal/bus/` embedded `nats-server` (flag-gated) + lifecycle wiring in `server.go`.
- [ ] `nats.go` client: publish `control.*`; subscribe `vulture.agent.>`.
- [ ] Config: `VULTURE_NATS_ENABLED`, `VULTURE_NATS_URL`, `VULTURE_NATS_HEARTBEAT_SEC`.

## Part B — Cancel triggers — ⬜ NOT STARTED
- [ ] Publish `cancel` on the 10-min timeout path (`agent_proxy_service.go:47`).
- [ ] `DELETE /api/audits/{id}` → mark `cancelled` → publish `cancel` (decision D3).

## Part C — Agent NATS client + control subscription — ⬜ NOT STARTED
- [ ] `shared/transport/nats_client.py` (new): connect in lifespan, presence + heartbeat.
- [ ] Per-run `{run_id → CancelToken}` registry + `vulture.audit.<run_id>.control` subscription.
- [ ] `_on_control` flips the Phase 0 token; unsubscribe + deregister on run end.

## Part D — Lifecycle / observability — ⬜ NOT STARTED
- [ ] Agent presence + heartbeat publishing.
- [ ] Backend live-agent view from presence/heartbeat.
- [ ] (D1, fast-follow) AgUI event mirror to `vulture.audit.<run_id>.event.<agent>`.

## Tests — ⬜ NOT STARTED
- [ ] T1 cancel-over-NATS · T2 degradation · T3 flag-off parity · T4 lifecycle · T5 registry hygiene · T6 Go embedded server · T7 multi-agent atomic cancel.

## Not done / follow-ups
- Frontend "Cancel audit" button (separate).
- Event-mirror tap (D1 fast-follow).
- Phase 2 collaboration fabric (separate spec).
- Optional JetStream durable replay (separate).
