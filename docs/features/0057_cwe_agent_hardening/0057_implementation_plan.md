# Feature 0057 — CWE Agent Hardening: LLM-On + Signature Detection + Verified Coverage

| | |
|---|---|
| **Feature** | 0057_cwe_agent_hardening |
| **Status** | 🟡 DRAFT — submitted for review (no code written) |
| **Date** | 2026-06-26 |
| **Depends on** | 0045 (validation phase), 0046 (L5 LLM judge), 0050 (CWE normalization) |
| **Source** | Deep-research "Improving Vulture's CWE Agent"; design workflows `research-cwe-agent-improvements` + `expand-0057-cwe-verification` (2 adversarial reviewers) |

> **Scope note (2026-06-26):** this feature **folds in** research #4 (per-CWE signatures) +
> #2 (labeled corpus + per-CWE recall gates) as **Phases 4–7**, per the maintainer's
> decision. The design workflow had recommended splitting these into a separate feature 0058;
> the maintainer chose to keep them in 0057. **The phases remain independently shippable** —
> Phases 0–1 (LLM-on) can land and roll back without Phases 4–6 (signatures/corpus). This is
> now a large, multi-phase feature (~5–8 person-weeks total); gate each phase before the next.

> **Numbering:** requirements R1–R9 + R10–R17, work items P0–P3 + P4–P6, tests T1–T12 +
> T13–T25, rollout Phases 0–7. Risks are numbered to avoid the `R`-prefix collision.

---

## 1. Goal

Two coupled goals:

1. **LLM phase on by default, after the deterministic phase** — so the LLM finds weaknesses
   the regex skills structurally cannot (dataflow, cross-file, semantic), batch-looped to
   sweep the whole codebase, and **verified** by the L5 judge so it doesn't flood. Skills
   stay authoritative.
2. **A deterministic signature tier + corpus-gated verified coverage** — sink/source/
   sanitizer signatures for high-value CWEs the skills miss, with **every counted CWE backed
   by a labeled corpus and a per-CWE recall/precision gate**, so we publish a **real, tested
   number of systematically-verified CWE types (N)** — computed by CI, never hand-asserted.

## 2. Motivation (verified by the research)

1. **The LLM phase is OFF by default.** `USE_LLM` defaults `false` (`audit_runner.py:64`);
   CWE passes `use_llm=None` (`agent.py:109,123`) → falls back to that false. The agent ships
   skills-only.
2. **The skills are the real coverage but cap at single-line lexical matching** — no AST/
   dataflow (`parse_ast` exported, never wired). They miss cross-line/semantic weaknesses.
3. **Turning the LLM on naively is net-negative** (28–88% FP vs Bandit,
   [arxiv 2606.11672](https://arxiv.org/html/2606.11672)). The control is the L5 judge — but
   today it's **off by default** (`audit_runner.py:795-800`) and **judges blind**:
   `AuditFinding` (`:46-55`) has no `code_snippet`.
4. **The "846 CWEs" is aspirational.** The keyword-overlap catalog detector
   (`catalog_detector.py:181-236`) fires **~0 findings** on real vulnerable code (reproduced
   empirically). Declared coverage ≠ verified coverage.

**Conclusion:** "LLM on" is only correct as a bundle (on + code-grounding + judge + cap +
sweep + tests); and "846 verified" is only honest if a corpus gate proves each CWE. This
feature delivers both.

## 3. Requirements

### LLM-on bundle
- **R1** CWE runs the LLM phase by default after the skill phase.
- **R2** The deterministic phase stays **authoritative**: no skill (or `trusted`-signature)
  finding is suppressed by the LLM phase alone (V6 voter 2-demoting-check floor, `voter.py:50`).
- **R3** LLM findings are **deduplicated** against deterministic findings (`audit_runner.py:744`).
- **R4** LLM findings are **verified by the L5 judge** before surfacing, and the judge sees a
  **real code window** (never blind).
- **R5** With no usable model, the agent **degrades gracefully** to skills-only + a notice,
  exit 0 (protects the Mode-E no-key user).
- **R6** A per-audit **cost/work cap** bounds the LLM phase; real token counts reported even
  for local models.
- **R6b** The LLM phase **covers the whole codebase**, not just the first context window — it
  iterates over file batches until the tree is analyzed or the budget (R6) is hit, never
  silently truncating.
- **R7** Python-only, **no DB migration**: `code_snippet` populates the **pre-existing**
  `code_snippet` column (`backend/internal/repository/migrations/001_init.sql:73`,
  `backend/internal/model/finding.go:28`) — it flows to the SSE `result` + the findings table
  (useful UI context). Secret-bearing CWEs (**798 hardcoded creds / 319 cleartext**) are
  **redacted** in the snippet before persist (Phase 2, P2a). *(Corrected 2026-06-27: the
  original "in-memory only" was wrong — the column predated this feature, so no migration.)*
- **R8** Other agents unchanged — the flip is CWE-scoped via the per-request override.
- **R18** *(provenance persists — scope-corrected 2026-06-27, per maintainer)* the agent's
  per-finding `provenance` MUST surface end-to-end at `GET /api/audits/:id` and the findings
  table (P6d). Supersedes P6b's original "in-memory only". Multi-implementation (sqlite +
  postgres + the migration runner).
- **R9** Determinism: skills + signatures stay deterministic; LLM is not. Business-logic
  tests use a **fake provider**; CI gates never call a live LLM.

### Signature tier + verified coverage (folded #4 / #2)
| ID | Requirement |
|---|---|
| **R10** | A **deterministic signature tier** detects CWEs via a declarative **sink + tainted-source + sanitizer** rule with a bounded line-window. Signatures are **data, not code**; the executor is one generic 3-step matcher. |
| **R11** *(BLOCKING)* | Signatures **route through `check_catalog_generic` + the `_DEDICATED_SKILL_CWES` ownership set** — NOT a parallel skill category. The dedup key is `(check_id, file_path)` (`audit_runner.py:546-552`, **confirmed**), so a parallel category would double-report one vuln under two CWE IDs. |
| **R12** | The keyword-overlap engine (`catalog_detector.py:181-236`, fires ~0) is **retired from the counted path**; the parent/child **rollup** (`:288-334`) is retained, fed from signature hits. |
| **R13** | A signature is **`candidate`** until its CWE passes a corpus gate, then **`trusted`**. Only `trusted` gets the voter 2-check floor; `candidate`s are L5-demotable like LLM findings. Promotion is **data-driven from the last corpus run**. |
| **R14** | A **labeled corpus** (positive + negative fixtures) backs every verified CWE. **First-party Apache-2.0 fixtures backbone + NIST Juliet 1.3 (CC0) for C/C++/Java only.** OWASP BenchmarkJava (GPL-2.0) and SecurityEval (unlicensed) **MUST NOT** be vendored. |
| **R15** | Two **per-CWE gates** on deterministic tiers only (no live LLM): **recall** + **clean-code precision (FP-rate)**. A CWE is **verified** iff ≥ `min_fixtures` positive AND ≥ `min_fixtures` clean AND meets `min_recall` AND `max_fp_rate` (`min_fixtures` default 3, anti-vacuity). |
| **R16** | **N is computed by the gate, never asserted.** A CI-regenerated `VERIFIED_CWES.md` distinguishes DECLARED-ONLY / CANDIDATE / VERIFIED / LLM-ASSISTED; stale → CI fail. |
| **R17** | Corpus gate runs a **curated subset on the PR lane** (< ~60s, deterministic); full sweeps on a **nightly/label lane**. Full Juliet (64,295 cases) MUST NOT hit the PR lane. |
| **R3′** | Replace "846 / 400+ via keyword matching" (`config.py:49`, `agent.py:26,29,69`, `SKILLS.md:3,272,283`) with "**N systematically-verified CWE types (see `VERIFIED_CWES.md`)**". |

## 4. Verified coverage — the honest N

**N is the number of CWE types Vulture can *prove* it detects, not the number it claims.** N
= CWEs that, on **deterministic detectors only** (skills + signatures, **no live LLM**), pass
a per-CWE gate on a committed corpus (≥3 vulnerable fixtures flagged + ≥3 safe twins not
flagged, clearing recall + FP thresholds). Computed by CI, published in `VERIFIED_CWES.md`.

| At | N | Basis |
|---|---|---|
| **Ship (tranche 1)** | **≈ 50–65** | skill CWE-IDs that *empirically pass* fixtures + 6–8 net-new signatures that pass |
| **Ceiling** | **≈ 80** | ~73 verified skills + ~7 signatures |
| Keyword catalog | **0** | fires ~0 on real code |
| LLM phase | **0 added to N** | reported separately as LLM-ASSISTED (non-deterministic) |

> Honest baseline: grep finds **84** distinct `CWE-N` strings in skill source; **~73** are
> emitted `category` literals. Declaration ≠ detection — which is why N is gate-computed.

**Three honesty tiers:** DECLARED (~73 skill / 846 catalog) → EMPIRICALLY-FIRING →
**CORPUS-GATED (= N)**. Only the last counts.

**Target signature CWEs (tranche 1)** — 8 of 13 proposed survived the adversarial cut as
honest, net-new, signature-tractable *without* dataflow/AST:

| CWE | Name | Lang(s) | Fixture (positive / clean twin) |
|---|---|---|---|
| **CWE-1333** | ReDoS (zero-dataflow; strongest) | JS/TS, Py, Java, Go | `firstparty/js/cwe_1333_redos.js` / `_clean` |
| **CWE-90** | LDAP Injection | Java, Py, JS/TS, PHP, C# | `firstparty/python/cwe_090_ldap.py` / `_clean` |
| **CWE-91** | XML/XPath Injection (complements CWE-611) | Java, Py, JS/TS, C#, PHP | `firstparty/java/Cwe091Xpath.java` / `_clean` |
| **CWE-917** | EL Injection (SpEL/OGNL/MVEL) | Java | `firstparty/java/Cwe917Spel.java` / `_clean` |
| **CWE-943** | NoSQL Injection (`$where`, CWE-89 misses) | JS/TS, Py, Java | `firstparty/js/cwe_943_nosql.js` / `_clean` |
| **CWE-117** | Log Injection | Java, Py, JS/TS, Go | `firstparty/go/cwe_117_loginj.go` / `_clean` |
| **CWE-548** | Info Exposure via Directory Listing | JS/TS, Java, Go | `firstparty/js/cwe_548_dirlist.js` / `_clean` |
| **CWE-489** *(provisional)* | Active Debug Code — kept only if corpus shows it's net-new vs the `configuration` skill | Py, JS/TS, Java, Go | `firstparty/python/cwe_489_debug.py` / `_clean` |

**Dropped** (would double-report): CWE-77 (≡ CWE-78), 119/120 (≡ `buffer_handling`), 377
(≡ CWE-676). **Deferred to the AST/dataflow tier** (need reachability): **CWE-121, CWE-73**.

## 5. Target architecture

```
Phase 1 — Deterministic detection (ALWAYS, authoritative)
    21 skills  +  signature tier (sink/source/sanitizer; trusted = voter 2-check floor,
    candidate = L5-demotable) — signatures route THROUGH check_catalog_generic (R11)
        → deterministic findings, 100% file coverage
        │
        ▼
Phase 2 — LLM enhancement (ON by default WHEN a usable model is configured)
    batch-loop over context-window-sized batches until the tree is covered or the budget
    is hit, WITH read/grep tools → candidates → dedup across batches AND vs deterministic
        │
        ▼
[ code_snippet attached to ALL findings ]
        │
        ▼
Phase 3 — Validation V6 (L1/L2 always; L5 judge ON when LLM on)
    L5 verifies LLM + candidate-signature findings against a REAL window (skip if empty);
    RC6 blast-radius cap; crypto/policy CWEs exempt; voter → high_confidence/suspicious/likely_fp
        │
        ▼
Result: skills + trusted-signatures (authoritative) + judge-verified net-new LLM findings,
        all code-grounded; deterministic coverage ATTESTED by the corpus gate (N)
```

No usable model → Phase 2 + L5 skipped, skills + signatures run, explicit notice, exit 0.

## 6. Detailed changes

Effort: S ≤1d · M 2–4d · L 1–2wk. Test-first per CLAUDE.md.

### Phase 0 — Code-grounding (shared infra; prerequisite)
| Item | What | Where | Effort |
|---|---|---|---|
| P0.1 | `code_snippet` field on the in-memory finding | `audit_runner.py:46` | S |
| P0.2 | `_attach_code_snippet()` central populator before `_validate` | `audit_runner.py:~760` | S |
| P0.3 | L5 skips findings with an empty window | `validate/llm_judge.py` | S |

### Phase 1 — LLM phase on, safely (CWE-scoped)
| Item | What | Where | Effort |
|---|---|---|---|
| P1a | CWE `use_llm` defaults True (model-gated) + provider-availability gate → graceful skills-only | `agent.py:109`; `shared/llm/health.py:93-104` | M |
| P1b | L5 judge defaults on when LLM on; **RC6 blast-radius cap**; **crypto/policy CWE exemption** | `validate/llm_judge.py:249`, `validate/__init__.py:224` | M |
| P1c | LLM gets read/grep tools on the inline path (`audit_runner.py:~1043`) | `audit_runner.py` | M |
| P1d | Cost/work cap (`VULTURE_LLM_MAX_FILES`, `VULTURE_LLM_BUDGET_USD`); honest token counts (incl. local) | `audit_runner.py:289-293,716-757,992-999` | M |
| P1f | **Whole-codebase batch-loop** — replace the single-shot `Runner.run` (`:1122`) with a batch loop (context-window-sized batches; dedup across batches + skills; stop at tree-covered or budget). Eliminates the silent tail-drop (`:289-293`) | `audit_runner.py:289-293,1122` | M |

### Phase 2 — Snippet redaction + soak-tuning
| Item | What | Where | Effort |
|---|---|---|---|
| P2a | **Redact `code_snippet` for secret-bearing findings** (CWE-798 hardcoded creds, CWE-319 cleartext): mask quoted string literals / assignment RHS in the window **before** it reaches the SSE `result` + the DB. TDD: a CWE-798 finding's snippet has the secret masked, structure preserved; non-secret findings untouched. | `audit_runner.py` (`_redact_snippet` in/around `_attach_code_snippet`) | M |
| P2b | Tune RC6 threshold, crypto-exempt set, budget defaults from real-audit soak telemetry | config/docs | — (soak) |

### Phase 3 — Docs (LLM-on)
| Item | What | Where | Effort |
|---|---|---|---|
| P3 | Document the new default + generate-verify + every env var | `agent.py`, `CLAUDE.md` | S |

### Phase 4 — Signature registry + detector
| Item | What | Where | Effort |
|---|---|---|---|
| P4a | `CweSignature` frozen dataclass (compiled-regex py modules, not JSON) | **add** `skills/signatures/schema.py` | S |
| P4b | Generic 3-step matcher (sink→source→sanitizer), ext-indexed, cyclomatic ≤ 4 | **add** `skills/signatures/detector.py` | M |
| P4c | Registry + per-family modules, introspectable by the gate | **add** `skills/signatures/registry.py` + families | M |
| P4d *(BLOCKING, R11)* | Route via `check_catalog_generic`; retain rollup + `_DEDICATED_SKILL_CWES`; remove keyword path; repoint `skills/__init__.py:81`. No new `ALL_CATEGORIES` entry | **change** `catalog_detector.py`, `skills/__init__.py` | M |
| P4e | Validation tiering (`trusted`→2-check floor, `candidate`→L5-demotable) | **change** `validate/voter.py:50`, `validate/types.py` | M |
| P4f | Seed the 7–8 net-new signatures as `candidate` | **edit** family modules | M |

### Phase 5 — Corpus + per-CWE gates
| Item | What | Where | Effort |
|---|---|---|---|
| P5a | Corpus tree + `manifest.yaml`; first-party Apache-2.0 + Juliet CC0 subset; add to `.vultureignore` | **add** `agents/cwe/tests/corpus/…` | **L** |
| P5b | `gates.yaml` + `corpus_runner.py` (per-CWE recall + FP, deterministic) | **add** `tests/corpus/…` | M |
| P5c | `promote_signatures.py` (data-driven candidate↔trusted) | **add** `scripts/promote_signatures.py` | M |
| P5d | License rows (Juliet CC0, first-party Apache-2.0); no GPL/unlicensed | **change** `THIRD_PARTY_LICENSES.md` + corpus `LICENSE.md` | S |
| P5e | CI: `make cwe-corpus` + PR curated subset (<~60s) + nightly/label full lane | **change** `Makefile`, `.github/workflows/ci.yml` | M |

### Phase 6 — Attestation + doc reconciliation
| Item | What | Where | Effort |
|---|---|---|---|
| P6a | `report_coverage.py` → golden `VERIFIED_CWES.md` (4 buckets); **N = VERIFIED rows**; stale → CI fail | **add** `tests/corpus/report_coverage.py`, `VERIFIED_CWES.md` | M |
| P6b | Per-finding `provenance` tag (agent-side, 6-value vocabulary) | **change** `audit_runner.py:760` | S |
| P6c | Replace "846/400+" with the attested N (docs + `test_catalog_detector.py`) | **change** docs + tests | S |
| P6d | **Provenance persistence (backend, R18)** — surface the agent's per-finding `provenance` at `GET /api/audits/:id` + the findings table. Multi-impl: add `Provenance` to `model.Finding` (mirror `CodeSnippet`); carry it through `stream_handler.go` (`parseSnapshot`/`extractDeltaFindings`); INSERT/SELECT in `sqlite_repo.go` + `postgres_repo.go`; add a `provenance` column (sqlite inline `ALTER TABLE` + a new gated postgres migration per `docs/guides/migration_authoring.md`). TDD: provenance round-trips. | **change** `backend/internal/model/finding.go`, `handler/stream_handler.go`, `repository/{sqlite,postgres}_repo.go` + migration | M |

**Honest total: ~5–8 person-weeks** (Phase 0–1 ≈ 1–2wk; Phase 4 ≈ 1.5wk; Phase 5 ≈ 2–3wk,
corpus + license review dominate; Phase 6 ≈ 2–3d). Large — hence the per-phase gates.

## 7. Configuration

| Env var | Default | Notes |
|---|---|---|
| `VULTURE_USE_LLM` (global) | `false` | unchanged; CWE overrides per-request |
| CWE `use_llm` | **True** (model-gated) | `false`/request override wins |
| CWE `validate_use_llm` (L5) | **True** when LLM on | request override wins |
| `VULTURE_LLM_MAX_FILES` | **10000** | high ceiling by design — file count is *not* the throttle; the context window + budget are |
| `VULTURE_LLM_BUDGET_USD` | off | hard stop on estimated spend (the real cost guard) |
| `VULTURE_CWE_DISABLE_LLM` | — | escape hatch: force skills+signatures only |
| `VULTURE_CWE_DISABLE_SIGNATURES` | — | escape hatch: skip the signature tier |
| `VULTURE_CWE_SIGNATURES_CANDIDATE_OFF` | — | run `trusted` signatures only |

## 8. Test plan — E2E business-logic first (fake provider; gate is LLM-free)

**LLM-on contracts (shared + cwe):** T1 code_snippet populated · T2 L5 skips blind ·
T3 skills authoritative · T4 LLM deduped · T5 RC6 cap · T6 graceful no-model · T7 budget cap ·
T8 CWE LLM on by default · T9 LLM finds a cross-line gap skills miss · T10 crypto not
auto-suppressed · T11 clean-code FP gate · T12 LLM sweeps beyond one context window.

**Signature + corpus contracts:** T13 signature detects cross-line gap (LLM OFF) · T14 dedup
precedence, no double-report (R11) · T15 candidate demotable / trusted needs 2 checks ·
T16 corpus runner scores per-CWE · T17 recall gate fails on regression · T18 per-CWE
precision gate · T19 min_fixtures anti-vacuity · T20 weak candidate not gating · T21
promotion data-driven · T22 `VERIFIED_CWES.md` golden not stale · T23 provenance tagged ·
T24 attestation counts reconcile · **T25** (opt-in, `VULTURE_E2E_LLM=1`, NOT gating) LLM
raises recall on dataflow fixtures, ranges not counts, never folded into N.

## 9. Rollout (soak → enforce; gate each phase)

0. **Phase 0** — code-grounding; T1/T2 green; no behavior flip. *(shippable alone)*
1. **Phase 1** — LLM-on + batch-loop + L5 behind the model-gated default; T3–T12 green. Soak. *(shippable alone)*
2. **Phase 2** — tune RC6/crypto-exempt/budget from soak.
3. **Phase 3** — LLM-on doc updates.
4. **Phase 4** — signatures land as `candidate` only; T13–T15; contributes 0 to N.
5. **Phase 5** — corpus + gates; promotion on; first `VERIFIED_CWES.md`; T16–T22.
6. **Phase 6** — attestation + "846/400+" reconciliation; T22–T24.
7. **Phase 7** — soak signatures + gate on real audits; tune `gates.yaml`; decide CWE-489; T25 LLM-lift measured, never gated.

## 10. Risks & mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | LLM FP flood | L5 generate-verify (R4) + skills authoritative (R2) + dedup (R3) + T11 |
| 2 | Cost blow-up (full sweep, cloud) | `VULTURE_LLM_BUDGET_USD` real guard (R6) + live token reporting; local = $0 |
| 3 | No-key / Mode-E breakage | model-availability gate → graceful skills-only (R5, T6) |
| 4 | Weak local models regress with tools/CoT | capability-aware gate; escape hatch |
| 5 *(BLOCKING)* | **Double-reporting** — dedup key `(check_id, file_path)`; an overlap-CWE signature on an already-flagged line emits twice | route ALL signatures through `check_catalog_generic` + `_DEDICATED_SKILL_CWES` (R11/P4d); ship only the 7–8 net-new CWEs |
| 6 *(BLOCKING)* | **Asserting N before the gate** repeats the "claims coverage that doesn't fire" error | N gate-computed in `VERIFIED_CWES.md`; stale → CI fail (T22); no N literal in source |
| 7 *(BLOCKING)* | **License** — GPL/unlicensed corpus wrecks the Apache-2.0 posture | first-party Apache-2.0 + Juliet CC0 (C/C++/Java only); GPL/unlicensed OUT (P5d) |
| 8 *(BLOCKING)* | **CI time** — full Juliet (64,295) on the PR lane | curated subset on PR (<~60s); full sweep nightly/label (R17/P5e) |
| 9 | Signature maintenance debt on CWE-version bumps | sigs are data; the per-CWE gate auto-demotes on regression (red CI) so rot surfaces as a failing gate |
| 10 | CWE-121 mislabeled regex-tractable (needs AST) | deferred to the dataflow tier; not in tranche 1 |
| 11 | Overstating "verified" | provenance vocabulary (P6b) + 4-bucket attestation; never a blanket flag |

## 11. Scope-lock — explicitly OUT (separate follow-ups)

- **AST/dataflow + bind-or-reject taint** (#8/#9) — incl. **CWE-121, CWE-73** (need
  reachability) — addressed by **feature [0058](../0058_semgrep_cwe_augmentation/0058_implementation_plan.md)** (standalone Semgrep taint tier augmenting the deterministic skills), not by hand-wiring `parse_ast`.
- **Incremental/diff analysis** (#14) — reusing parsed facts across runs; deferred.
  *(LLM chunk-looping #15 is IN scope — P1f.)*
- **Dark-skills wiring** `secret_scan`/`plaintext_transmission` (#1) — 1-line config fix;
  independent.
- **Commit-keyed audit cache** (#5) — backend correctness fix; independent.

## 12. Open decisions — for review

1. **MAX_FILES** — ✅ **decided (2026-06-26):** `VULTURE_LLM_MAX_FILES=10000` (uncapped by
   file count; context window + USD budget bound the sweep). USD cap off by default — confirm.
2. **LLM defaults** — CWE-only · on-when-model-available · L5 on · L5 only re-ranks skill
   findings within the 2-check floor · `code_snippet` **persists** to SSE+DB (pre-existing column; R7 corrected) **with redaction** for secret-bearing CWEs. ✅ confirmed.
3. **Signature tranche** — 7 solid net-new, or include the provisional CWE-489 from the start
   (gate decides either way)?
4. **Juliet supplement** — vendor a curated CC0 Juliet subset for C/C++/Java (bigger N), or
   first-party-only to start?
5. **Gate strictness** — `min_recall=1.0 / max_fp_rate=0.0 / min_fixtures=3` — keep or relax?
6. **PR-gate enforcement** — block PRs on the curated-subset gate immediately, or advisory
   then enforce (soak first)?

## 13. Acceptance criteria

- ☐ T1–T24 green; existing CWE + shared suites still green.
- ☐ With a usable model, CWE runs LLM by default + reports ≥1 finding on the T9 dataflow
  fixture that skills-only misses; with no model, skills+signatures only + notice, exit 0.
- ☐ Every finding entering L5 carries a real window (or is skipped); a repo larger than one
  context window is swept in multiple batches.
- ☐ The 7–8 signatures route through `check_catalog_generic`; **no** double-reporting (T14).
- ☐ `VERIFIED_CWES.md` generated by CI; **N reproducible** via `pytest agents/cwe/tests/corpus/`; stale → CI fail.
- ☐ Every verified CWE has ≥3 positive + ≥3 clean fixtures and passes recall + FP gates.
- ☐ No GPL/unlicensed corpus vendored; `THIRD_PARTY_LICENSES.md` updated; PR gate < ~60s.
- ☐ "846/400+" replaced by the attested N across docs + tests.
