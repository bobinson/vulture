# Feature 0059 — Rollback Plan

## Blast radius
- **`--fresh`** — tiny + additive. New per-audit config key `fresh` (default off) + a flag on two clients. No schema change, no env var, no change to default behavior (memory stays ON unless `fresh:true`).
- **Tier‑3 toggle** — **changes the default LLM scope** (whole-tree → T1+T2 only) once built; this is its only non-additive aspect. Deterministic coverage and the verified-N are unaffected. The mandatory skip notice (R10) makes the reduced scope visible.

## Instant disable (no deploy)
- **`--fresh`:** simply don't pass it — absent/false keeps memory ON (prior behavior). Opt-in per audit, so there's no toggle to flip.
- **Tier‑3 toggle:** set `VULTURE_LLM_TIER3=on` (deployment-wide) — restores the previous whole-tree LLM behavior instantly, no deploy. Per scan: pass `--llm-tier3`. (And because it defaults OFF, the *new* behavior is the conservative one — rolling "forward" to full coverage is the env flip, not a revert.)

## Full revert (code) — `--fresh`

## Full revert (code)
1. `backend/internal/handler/stream_handler.go` — delete `auditRequestsFresh`; restore both dispatch sites to the unconditional `priorByAgent := h.loadPriorFindings(...)`. Remove `TestAuditRequestsFresh`.
2. `scripts/dev/scan.py` — remove the `--fresh` arg + the `config` var (revert to `"config": {}`).
3. `cli/main.go` — revert `parseScanFlags` signature (drop `fresh`), the `--fresh` case, the two call sites, `cmdScan` signature, the config-merge block (restore the `if validateLLM` overwrite), and the usage line.
4. Delete `docs/features/0059_fresh_scan_memory_bypass/`.

A stray `{"fresh":true}` in a stored audit config after revert is harmless — the backend simply ignores the unknown key.

## Full revert (code) — Tier‑3 toggle *(once built)*
1. `agents/shared/shared/audit_runner.py` — delete `_llm_tier3_enabled`; drop the `include_tier3` kwarg from `_prioritize_files` (restore unconditional `tier1+tier2+tier3`); remove the filter + skip-notice at both LLM-input call sites; drop the `llm_tier3` threading through `run_combined_audit`.
2. Remove the Tier‑3 tests (T7–T12).
3. `cli/main.go` + `scripts/dev/scan.py` — remove the `--llm-tier3` flag wiring.
A stray `{"llm_tier3":true}` / `VULTURE_LLM_TIER3` after revert is harmless (ignored). Reverting restores whole-tree LLM scanning (higher cost) — the opposite of a cost regression.

## Verify after revert
- `cd backend && go vet ./... && go test ./internal/handler/`
- `cd cli && go build ./... && go vet ./...`
- `python -m py_compile scripts/dev/scan.py`
