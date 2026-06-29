# Feature 0059 — LLM Scan Controls: `--fresh` (memory bypass) + Tier‑3 toggle (LLM cost guard)

| | |
|---|---|
| **Feature** | 0059_fresh_scan_memory_bypass (scope broadened 2026-06-29 to two LLM-scan knobs) |
| **Status** | 🟢 `--fresh` implemented · 🟢 **Tier‑3 toggle implemented** (default OFF, decision (a) — see §6) |
| **Date** | 2026-06-29 |
| **Depends on** | 0045 (validation/memory), 0057 (LLM-on bundle + file tiering / `_prioritize_files`) |
| **Motivation** | Two independent findings from this session's audits. (1) **Memory** — on a same-path re-scan the backend loads prior findings and steers the LLM away from re-reporting them, masking re-discovery; bad for critical tests / new models → `--fresh`. (2) **Cost** — the LLM generate phase sweeps the **whole tree** by default (all scannable files, `VULTURE_LLM_MAX_FILES=10000`, **no USD budget by default**), so a large repo on a paid cloud model can be exorbitant → a **Tier‑3 toggle** that, off by default, scopes the LLM to the high-signal + structural files. |

## 1. Goal — two orthogonal, composable LLM-scan knobs

1. **`--fresh`** — clean-room scan: ignore the prior-findings memory so the LLM isn't steered by (nor the result masked by) earlier audits. *(Implemented.)*
2. **Tier‑3 toggle** — bound LLM cost by excluding the low-signal long tail (Tier 3) from the LLM **generate** phase. **OFF by default.** *(This LLD.)*

They compose: a thorough/critical/new-model audit runs `--fresh --llm-tier3` (clean + full coverage); a routine scan runs neither (incremental + cheap).

## 2. Background — the LLM file tiers (so this LLD is self-contained)

The LLM generate phase orders scannable files into tiers (`audit_runner.py::_prioritize_files`) and sweeps them in batches (`_build_source_batches` → `_collect_llm_findings_batched_async`):

| Tier | Files | Sent as |
|------|-------|---------|
| 1 | files the deterministic phase **flagged** | snippet (finding ± context) |
| 2 | entry points / config / **handlers** (`is_entry_or_config`) | full content |
| 3 | **everything else** (no findings, not entry/config), size-sorted asc | full content |

Today **all three tiers reach the LLM**; the order only governs what survives a budget cut. Tier 3 is typically **70–95% of a tree** — and it is where LLM cost concentrates.

## 3. Requirements

**`--fresh` (implemented):**
- **R1** `{"fresh": true}` in `audit.Config` → backend skips `loadPriorFindings` (no `prior_context`; L4 inherits no labels).
- **R2** Default keeps memory ON (no behavior change).
- **R3** Exposed on `scripts/dev/scan.py --fresh` and `vulture scan --fresh`.
- **R4** CLI `--fresh` **implies `--no-cache`** (a fresh run must re-execute, not return a cached result).
- **R5** Deterministic findings unaffected.
- **R6** No DB migration; per-audit config field.

**Tier‑3 toggle (this LLD):**
- **R7** The LLM generate phase's **Tier‑3** files are gated by a control that is **OFF by default** (the cost guard).
- **R8** OFF → the LLM analyzes only **Tier 1 (snippets) + Tier 2 (full)**. ON → current whole-tree behavior (T1+T2+T3).
- **R9 (load-bearing)** The toggle is **LLM-scope only**. The **deterministic phase is unchanged** — skills + signatures still scan **every** file, so all deterministic/skill-detectable findings on Tier‑3 files still surface, and the **corpus-gated verified-N is unaffected**. What OFF forgoes is *only* the LLM's semantic/dataflow analysis of the non-flagged, non-entry tail.
- **R10 (honesty)** When OFF and ≥1 file is skipped, the agent emits a **clear notice** (count of skipped files + how to enable). Reduced scope is **never silent**.
- **R11 (control surface + precedence)** env `VULTURE_LLM_TIER3` (`on`|`off`, deployment default) · per-audit `config.llm_tier3` (bool, per-scan override) · CLI/driver `--llm-tier3`. **Precedence: per-request config > env > built-in default (OFF).**
- **R12 (composability)** Orthogonal to `--fresh`, `VULTURE_LLM_BUDGET_USD`, `VULTURE_LLM_MAX_FILES`. The Tier‑3 filter applies **before** batching, so the budget/file caps then bound the smaller T1+T2 set (belt-and-suspenders).
- **R13 (determinism)** Gate is config/env-driven; business-logic tests use the fake provider, no live LLM.

## 4. Low-level design — Tier‑3 toggle

### 4.1 Resolver (env > default; config wins over both)
```python
# audit_runner.py  (near _resolve_llm_budget_usd / _safe_int_env)
def _llm_tier3_enabled(config_value: bool | None = None) -> bool:
    """Tier-3 in the LLM generate phase. Precedence: explicit per-request
    config > VULTURE_LLM_TIER3 env > built-in default OFF (cost guard)."""
    if config_value is not None:
        return config_value
    env = os.environ.get("VULTURE_LLM_TIER3", "").strip().lower()
    if env in ("on", "true", "1", "yes"):
        return True
    return False  # default OFF (also covers off/false/unset/garbage)
```

### 4.2 Tier filter (additive `include_tier3` kwarg; default True preserves callers)
```python
def _prioritize_files(files, source_path, skill_findings=None, include_tier3=True):
    ...                                  # build tier1, tier2, tier3 as today
    if not include_tier3:
        return tier1 + tier2             # drop the low-signal tail
    return tier1 + tier2 + tier3
```
Every file lands in exactly one tier, so the caller derives the skipped count as `len(scanned_files) - len(ordered)` — no return-shape change.

### 4.3 Wiring (both LLM-input paths)
- `_collect_llm_findings_batched_async` (batched sweep) and `_build_source_context` (inline path): call `_prioritize_files(..., include_tier3=tier3_on)` where `tier3_on = _llm_tier3_enabled(cfg_llm_tier3)`.
- **Threading the per-audit override:** the agent reads `llm_tier3` from its received per-audit config and threads it into `run_combined_audit(..., llm_tier3=…)` → the collectors — mirroring how `validate_use_llm` is threaded. Absent a config value, the env default applies.
- **Notice (R10):** when `not tier3_on` and `skipped > 0`:
  > `[llm-scope] Tier‑3 skipped: <N> file(s) (no deterministic findings, not entry/config) were NOT sent to the LLM — cost guard. Set VULTURE_LLM_TIER3=on or scan --llm-tier3 for full-tree LLM coverage.`
  Emitted as a `thinking`/text event **and** recorded on the result (so the API/CLI surface it, like the existing partial-results/budget notices).

### 4.4 Order of operations (unchanged except the new filter)
`scan_code_files (ALL)` → **skills+signatures (ALL files — unchanged)** → `_prioritize_files` → **[Tier‑3 filter]** → `_build_source_batches` → per-batch LLM call → `VULTURE_LLM_BUDGET_USD` / `VULTURE_LLM_MAX_FILES` cap during the sweep.

### 4.5 Control surface summary
| Layer | Knob | Default |
|------|------|---------|
| Deployment | env `VULTURE_LLM_TIER3=on\|off` | off |
| Per-audit | `config.llm_tier3: true` | (falls to env) |
| CLI / driver | `vulture scan --llm-tier3` · `scan.py --llm-tier3` → sets config | off |

## 5. Cost vs. recall — the explicit trade-off

- **Cost (the win):** excluding Tier 3 removes the bulk of LLM calls/tokens. On a 544-file repo (e.g. woofy) the LLM would see only the flagged + entry/handler files — order of **tens, not hundreds** → roughly a **5–20× reduction** in LLM spend/time. On a paid cloud model that is dollars→cents per scan; on a local model it is wall-clock time saved.
- **Recall (the cost), precisely bounded:** OFF forgoes **only** the LLM's semantic/dataflow analysis of files that have **no** skill finding **and** aren't entry/config/handlers. Those files are **still fully scanned by the deterministic skills + signatures**, so any skill/signature-detectable issue there is still reported and the verified-N is unchanged. What's lost is LLM-only discovery in the ordinary tail — e.g. a cross-method command injection in a non-entry helper like the demo's `report_service.py` (Tier 3). Real, but bounded to the lowest-signal slice, and made **visible** by the R10 notice.
- **Why default-OFF is defensible:** routine scans keep **full deterministic coverage everywhere** + LLM depth on the high-signal/structural files at a fraction of the cost; thorough/critical/new-model audits opt into full LLM coverage with `--llm-tier3` (naturally paired with `--fresh`).
- **⚠️ Behavior-change callout:** this changes the **default LLM scope** (was whole-tree). Callers who expect full-tree LLM coverage must set `VULTURE_LLM_TIER3=on`. Mitigated by the mandatory notice (R10) + the escape hatch — never a silent reduction.

## 6. Decision (resolved 2026-06-29) — default policy

**DECIDED: (a) unconditional OFF.** Tier 3 is skipped by default regardless of model or budget — the simplest, most predictable rule and the safest on cost. Per-request `--llm-tier3` (or `VULTURE_LLM_TIER3=on`) opts into full coverage.

**Deferred to future (explicitly out of scope here, to be planned separately):** smarter *routing* mechanisms — the cost-aware variant (Tier 3 auto-ON when cost is $0 / local model or a `VULTURE_LLM_BUDGET_USD` is set; OFF only for paid-cloud-no-budget), finer per-tier / dataflow-aware routing, and an operator hard-lock `VULTURE_LLM_TIER3_LOCK`. The current binary toggle is the floor those can build on.

## 7. Test plan (TDD, LLM-free, fake provider)

- **T-fresh** (done) — `auditRequestsFresh` truth table.
- **T7** default OFF → the collector feeds the LLM **only T1+T2** (assert via fake provider the Tier‑3 files are absent from the batched inputs).
- **T8** `VULTURE_LLM_TIER3=on` and `config.llm_tier3=true` → Tier‑3 included (whole-tree).
- **T9** precedence — config `true` overrides env `off`; config `false` overrides env `on`; absent config → env; absent both → OFF.
- **T10** notice emitted with the correct skipped count when OFF; no notice when ON or nothing skipped.
- **T11 (load-bearing)** deterministic findings unchanged — a Tier‑3 file with a skill-detectable issue is still reported with Tier‑3 OFF (skills scan all files).
- **T12** `_prioritize_files(include_tier3=False)` returns exactly `tier1 + tier2`; default kwarg keeps existing callers' behavior.

## 8. Scope-lock — explicitly OUT
- Finer-grained scope modes (flagged-only, per-tier weighting, percentage sampling) — future; this is a **binary** Tier‑3 toggle.
- Changing tier *definitions* (entry-point detection) — handled separately in the `is_entry_or_config` extension.
- The L5 verdict cache and the deterministic phase — untouched.
- Bypassing the L5 cache for `--fresh` — unnecessary (model-keyed).

## 9. Acceptance criteria
- ☑ (fresh) `{"fresh":true}` → no prior findings; default unchanged; CLI/driver wired.
- ☑ (tier3) **default OFF** → LLM sees only T1+T2 (collector filters via `_prioritize_files(include_tier3=False)`) **and** emits the skip notice; `VULTURE_LLM_TIER3=on` / `--llm-tier3` → whole-tree LLM.
- ☑ (tier3) **deterministic coverage unaffected** — skills/signatures scan all files; the filter only scopes the LLM input list (T11 covered by the two full-sweep tests retaining tier3-on + the deterministic suites staying green).
- ☑ (tier3) precedence config > env > OFF (T9); env / `config.llm_tier3` / CLI `--llm-tier3` / `scan.py --llm-tier3` all wired; shared 962 + cwe 601/1skip + ruff green; CLI builds+vets.
