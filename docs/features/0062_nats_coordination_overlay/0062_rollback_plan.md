# Feature 0062 — Rollback Plan

## Blast radius

Additive and flag-gated. With `VULTURE_NATS_ENABLED=false` (the default) the feature is inert: no NATS connection is attempted, no embedded server starts, and the audit path is byte-identical to pre-0062 (HTTP/SSE + Phase 0 disconnect-cancellation). The embedded broker binds loopback/unix-socket by default, so nothing is exposed on the network in Modes A/E.

**Correctness is never coupled to NATS:** even with the flag on, an unreachable broker degrades to the Phase 0 disconnect path — so disabling or removing NATS can only ever return the system to Phase 0 behavior, never break audits.

## Instant disable (no deploy)

Set `VULTURE_NATS_ENABLED=false` and restart the affected services (backend and/or agents). Effect is immediate:
- Backend stops the embedded server and closes its client.
- Agents skip NATS connect/subscribe; cancellation reverts to the Phase 0 disconnect path.
- In-flight audits are unaffected (control-plane only; audit transport was never on NATS).

## Full revert (code)

Because the feature is layered, revert in dependency order (agents and backend are independent — either can be reverted alone):

**Agents**
1. Remove `shared/transport/nats_client.py`.
2. Remove the lifespan connect/presence/heartbeat hooks and the per-run `{run_id → CancelToken}` registry + control subscription from `shared/transport/sse_app.py`.
3. Leave **Phase 0 intact** — the `CancelToken`, contextvar, transport wiring, and batch-loop checkpoints are the prerequisite, not part of the NATS revert. Disconnect-driven cancellation continues to work.

**Backend**
1. Remove `internal/bus/` (embedded server) and its startup/shutdown wiring in `server.go`.
2. Remove the `cancel` publish at the timeout site (`agent_proxy_service.go`); the pre-existing `context.WithTimeout` + connection close remains.
3. Remove the `DELETE /api/audits/{id}` cancel route (decision D3), if merged.
4. Drop `VULTURE_NATS_*` from `internal/config/config.go`.

**Dependencies**: remove `github.com/nats-io/nats-server/v2` + `nats.go` from `go.mod`; remove `nats-py` from the shared agent requirements.

## Verify after revert

- `VULTURE_NATS_ENABLED` unset ⇒ backend and agents start with no NATS log lines; `/health` green.
- Trigger an audit and let the backend timeout fire (or drop the client) ⇒ Phase 0 stops the agent's LLM sweep within one batch (≤1 in-flight). This is the invariant the revert must preserve.
- Full agent test suite (`shared`, all agents) + backend `go test ./...` green.
- No `nats` references remain: `grep -rli nats backend/ agents/ | grep -v node_modules` is empty.
