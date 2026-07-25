# 0027 Rollback Plan

## Risk Assessment

**Risk Level:** Medium — changes are additive to existing services. No database migrations. No API contract changes.

## Rollback Steps

### If pipeline wiring causes issues (Tasks 1-5, Go backend):

1. Revert `stream_handler.go` — remove `pipelineSvc.AdvanceStage()` call from `persistResults`, remove `RunPipelineStage` / `runPipelineAudit` / `consumeEventsNoSSE`
2. Revert `server.go` — restore `registerPipelineRoutes` to pass `nil` for discoverSvc, remove `SetRunner` call, remove streamH connection
3. Revert `pipeline_service.go` — restore `advanceToNextStage` to status-only update, restore `CreatePipeline` to not launch first audit, remove `PipelineRunner` interface and `runner` field

**Impact:** Pipeline API still works for tracking but doesn't auto-cascade. Individual agents continue to work independently. No data loss.

### If auto-execution causes runaway goroutines (Task 2b specifically):

1. Remove `pipelineSvc.SetRunner(streamH)` line from `server.go` — `runner` stays nil, `RunPipelineStage` calls become no-ops
2. Pipeline audits are created but must be triggered manually via `GET /api/audits/:id/stream`

**Impact:** Pipeline creates correct audit records with proper configs, but requires client-initiated streaming. Minimal code change, no data loss.

### If discover scan-results consumption causes issues (Tasks 6-7, Python):

1. Set `ignore_scan_results: true` in discover config — immediate disable, no code change needed
2. Or revert `discover/agent.py` — remove `_fetch_scan_findings`, `_extract_routes_from_findings`, and scan enrichment block

**Impact:** Discover reverts to URL-only + source-code discovery. No data loss.

### If prove graceful degradation causes issues (Task 8, Python):

1. Revert `prove/agent.py` — restore "No findings to verify. Run a scan first." exit behavior

**Impact:** Prove requires pre-existing scan findings again. No data loss.

## Monitoring

- Check backend logs for `[persist] advance pipeline stage:` errors
- Check discover agent logs for `Failed to fetch scan findings from backend:` warnings
- Monitor pipeline status in `GET /api/pipelines` — stuck `*_running` states indicate broken cascade

## Feature Flag

The `ignore_scan_results` config option on the discover agent acts as a partial feature flag. Setting it to `true` disables the scan-results consumption path entirely without requiring a code deploy.

## Isabelle Verification (Chunk 0)

The `verification/` directory is independent of all application code. It never needs to be rolled back — the proofs and oracle are correct regardless of implementation state.

- `verification/isabelle/` — Isabelle proofs are permanent mathematical truths. No rollback needed.
- `verification/oracle/` — The oracle binary can be kept. Conformance tests will fail if Go implementation diverges, which is the intended behavior.
- `verification/simulated-target/` — Standalone HTTP server, no dependencies. Can be kept regardless of implementation state. Useful for manual testing.
- `verification/conformance/` — Pure conformance tests can be disabled by removing `make verify` from CI. Simulation tests (`make verify-simulate`) can be disabled independently if the simulated target causes CI flakiness.

## DO-178C Verification Artifacts

If rollback is needed, the traceability matrix (`0027_traceability_matrix.md`) should be updated to reflect which requirements are no longer satisfied. Requirements marked **PROVEN** (REQ_027_F01–F11) remain proven regardless — the Isabelle theorems are unconditional. Requirements marked **DAL-C** need their tests to be updated or removed.

Robustness tests (Task 13) are additive — they test error paths that exist regardless of this feature, so they can be kept even after rollback.
