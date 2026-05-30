# 0046 — Status

## Current phase

**IMPLEMENTED — third-pass audit fixes landed (2026-05-25).** All
twelve build-sequence steps complete (2026-05-23). First audit
(22 items) addressed (2026-05-23). Third adversarial line-by-line
audit (32 items across correctness / security / concurrency) all
addressed (2026-05-25). Cache implemented as local SQLite file (not
the planned `audit_memories.l5_verdict_cache` column — that's a
Phase-2 cross-deployment cache; column kept for forward compat).

## Test coverage

| Suite | Tests | Status |
|---|---|---|
| `tests/unit/validate/` (Python L1-L5 + cache + parity) | 108 | ✅ all pass |
| `backend/internal/agui/` (translator) | full | ✅ all pass |
| `backend/internal/handler/` (stream) | full | ✅ all pass |
| Frontend `tsc --noEmit` | strict mode | ✅ clean |
| CLI binary | rebuild | ✅ clean |

Pre-existing `test_file_scanner_ignore` failures (6) are unrelated to feature 0046.

## Decisions log

| ID | Decision | Status | Locked by |
|---|---|---|---|
| D1 | L5 runs after L1+L2, before vote | ACCEPTED | initial design |
| D2 | Language detection by file extension only | ACCEPTED | initial design |
| D3 | Cache key = (file_sha256, line_range, check_id, model_name) | ACCEPTED | initial design |
| D4 | **`validate_llm_top_n` default = 1000** | **LOCKED 2026-05-23** | reviewer Q1 |
| D5 | L5 weight ∈ [−0.75, +0.75]; not authoritative | ACCEPTED | initial design |
| D6 | **Streaming verdicts per batch via `validation_update` SSE event** | **LOCKED 2026-05-23** | reviewer Q2 |
| D7 | L5 runs before L4 (no Python↔Go round-trip in v1) | LOCKED 2026-05-23 | reviewer Q3 (Phase 2 deferred) |
| D8 | **No authoritative-positive checks; `AUTHORITATIVE_CHECKS = {"suppression"}`** | **LOCKED 2026-05-23** | reviewer Q3 ("do the best after audits") |
| D9 | Migration 019 adds `l5_verdict_cache` JSONB column on `audit_memories` | ACCEPTED | initial design |
| D10 | Prompt files (`.txt`) version-controlled separately | ACCEPTED | initial design |
| D11 | **Ship local-model recipe in `SKILLS.md` + auto-detect what's loaded** | **LOCKED 2026-05-23** | reviewer Q4 |
| D12 | **L5 model default = `VULTURE_LLM_MODEL`; override via `VULTURE_VALIDATE_LLM_MODEL`** | **LOCKED 2026-05-23** | reviewer Q5 |
| D13 | Total L5 budget = 300 s (5 min) — scales with top_n=1000 | LOCKED 2026-05-23 | ultrathink |
| D14 | One JSON-parse retry per batch | LOCKED 2026-05-23 | ultrathink |
| D15 | Structured outputs preferred (`json_schema` → `json_object` → prompt) | LOCKED 2026-05-23 | ultrathink |
| D16 | V8 applied per-verdict-emission in streaming mode | LOCKED 2026-05-23 | ultrathink |
| D17 | Auto-select non-embedding model from `/v1/models` | LOCKED 2026-05-23 | ultrathink |
| D18 | Default concurrency = 5 (was 3) for top_n=1000 throughput | LOCKED 2026-05-23 | ultrathink |
| D19 | SSE event emitted per batch, not per verdict (100 events/audit max) | LOCKED 2026-05-23 | ultrathink |
| D20 | Startup warning if `l5_verdict_cache` column missing | LOCKED 2026-05-23 | ultrathink |

## Cost / latency profile (at locked defaults)

| Model | Per-audit cost | Wall-clock L5 latency |
|---|---|---|
| Local LM Studio / Ollama (qwen3:8b) | $0 | 3–10 min |
| gpt-4o-mini (hosted) | ~$0.20 | 40–90 s |
| gpt-4o (hosted) | ~$3.40 | 30–60 s |
| Claude Sonnet (hosted) | ~$4.35 | 40–90 s |

Streaming mitigates the local-model latency UX — verdicts visible
incrementally throughout the 3–10 min run.

## Build progress

- [ ] **1. Migration 019** — adds `l5_verdict_cache` column + index
- [ ] **2. Language detector** + unit tests
- [ ] **3. Prompt files** committed + render-snapshot test
- [ ] **4. `llm_judge.py` skeleton** behind flag (returns empties)
- [ ] **5. Live LLM path** — batched calls, structured outputs, retry
- [ ] **6. Streaming SSE** — new `validation_update` event type in
      Python emitter + Go translator + frontend handler
- [ ] **7. Per-emission V8** — apply compliance mode inline before SSE
- [ ] **8. Caching** — read/write `l5_verdict_cache`, fast-path emit
- [ ] **9. Model auto-selection** — `/v1/models` query + filter
- [ ] **10. CLI flags** — `--validate-llm`, `--validate-llm-top-n`
- [ ] **11. Audit-handler config passthrough**
- [ ] **12. Acceptance criteria 1–12** verified

## Phasing reminder

- **Phase 1 (this feature)**: L5 opt-in with all locked decisions
  above. Default off; reviewer's locked defaults take effect when
  enabled.
- **Phase 2 (separate feature)**: feed L5 verdicts back into L4's
  labelled corpus as weak labels. Reorder L5↔L4 if benchmarks justify
  the Python↔Go coupling cost.
- **Phase 3 (separate feature)**: tune `top_n` based on real-audit
  cost data; potentially enable L5 by default for hosted-LLM users.

## Review checklist

All boxes checked by reviewer on 2026-05-23:

- [x] D4 default (top_n=1000) — locked
- [x] D6 streaming — locked enabled
- [x] D8 authoritative-positive — locked no
- [x] D11 local model recipe — locked, will ship
- [x] D12 same model as audit — locked, with override
- [x] Risks table (in plan §Risks) — reviewed; hallucination + cost
      mitigations adequate at top_n=1000
- [x] Acceptance criteria — measurable; bucket-shift threshold raised
      from 15% to 25% to reflect top_n=1000 coverage
- [x] Files touched estimate — ~600 net LOC plus frontend
      `validation_update` handler (~50 LOC)

## Ready-to-start signal

Implementation can begin with build step 1 (migration 019) on
reviewer confirmation. Plan, status, and rollback are finalised.
