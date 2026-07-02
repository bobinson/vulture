# Feature 0057 — Rollback Plan

| | |
|---|---|
| **Feature** | 0057_cwe_agent_hardening (LLM-on + signatures + verified coverage) |
| **Status** | 🟡 DRAFT |
| **Last updated** | 2026-06-26 |

## Blast radius

Python + (Phases 4–6) a new test-corpus data asset + a CI lane. **No DB migration, no
SSE-contract change, no Go change** — `code_snippet` and `provenance` are in-memory; signature
modules, `corpus/`, and `VERIFIED_CWES.md` are new files. All behavior is additive and
opt-out; rollback is fast and per-phase. The corpus (Juliet CC0 subset) is the only
third-party-licensed asset added; removal is a file delete. Other agents are untouched.

## Kill switches (instant, no deploy)

| Action | Effect |
|---|---|
| `VULTURE_CWE_DISABLE_LLM=true` | CWE back to deterministic-only (skills + signatures) |
| `VULTURE_USE_LLM=false` (global default) | LLM off for any agent not self-overriding |
| `VULTURE_USE_VALIDATE_LLM=false` / request `validate.llm=false` | Disable L5 judge, keep LLM generation |
| `VULTURE_CWE_DISABLE_SIGNATURES=true` | Skip the signature tier → skills + (retained) catalog rollup + gated LLM |
| `VULTURE_CWE_SIGNATURES_CANDIDATE_OFF=true` | Run `trusted` signatures only (drop `candidate` L5 load + FPs) without losing gated coverage |
| `VULTURE_DISABLE_VALIDATE=true` | Disable the whole validation stage (L1/L2/L5) — emergency only |

The model-availability gate (R5) means a no-model environment already degrades to
deterministic-only automatically — a misconfig never hard-fails. Because promotion is
data-driven, a regressing `trusted` CWE auto-demotes to `candidate` (red CI) before it
misleads — the gate is itself a rollback mechanism.

## Staged code rollback (highest-numbered phase first)

1. **Revert Phase 6 (attestation)** — drop provenance tags + `VERIFIED_CWES.md` + doc edits.
   Additive, in-memory; safe to leave.
2. **Revert Phase 5 (corpus/gates)** — delete `corpus/` + the `cwe-corpus` CI lane. No
   promotion source → all signatures fall back to `candidate` (never authoritative). Phase 4
   still runs, demotable-only. No runtime failure.
3. **Revert Phase 4 (signatures)** — restore the original `check_catalog_generic` body +
   `_DEDICATED_SKILL_CWES`; repoint `skills/__init__.py:81` to the keyword detector. Agent
   returns to skills + catalog rollup + LLM. Independent of Phases 0–3. *(Optionally keep
   `check_catalog_generic` as a thin alias for one release.)*
4. **Revert Phase 1 (LLM flip)** — restore CWE `use_llm`/`validate_use_llm` to `None`
   (env-default-off) in `agent.py`. Immediately skills(+signatures)-only. Phase 0 stays
   (harmless).
5. **Revert Phase 0 (code-grounding)** — only if necessary. Remove `_attach_code_snippet` +
   the field. Safe to leave: with LLM/L5 off, the populator runs but nothing consumes it.

## Data considerations
- **None at the DB/schema level** — no migration. Removal leaves no orphaned state.
- The corpus is the only third-party-licensed asset (Juliet CC0); removal is a file delete.
- `VERIFIED_CWES.md` is generated; regenerate via `cd agents/cwe/tests/corpus && python report_coverage.py --write` (the staleness check is enforced by the unit tests under `agents/cwe/tests/unit/`: `pytest agents/cwe/tests/unit/test_report_coverage_*.py`).

## Verification after rollback
- `agents/cwe`: `python -m pytest tests/unit/ -q` green.
- A skills-only audit reports deterministic findings + no LLM phase ("LLM phase skipped");
  no `llm_phase_start` log for CWE; cost/token events report deterministic-only.

## Trigger conditions
- FP rate on real audits exceeds the soak gate (LLM or signature).
- LLM cost/latency regression beyond budget.
- L5 demoting real findings despite RC6 + crypto exemption.
- A `trusted` CWE's corpus recall/precision regresses below its gate on the nightly lane.
- The corpus PR lane exceeds its ~60s budget.

First response is always a **kill switch** (runtime), then a **staged code revert** if the
issue is structural.
