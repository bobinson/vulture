# Feature 0058 — Implementation Status

| | |
|---|---|
| **Feature** | 0058_semgrep_cwe_augmentation |
| **Status** | 🟡 DRAFT — awaiting review approval. No code written. |
| **Last updated** | 2026-06-26 |
| **Depends on** | 0051–0053 (plugin arch + bundled Semgrep), 0057 (corpus harness + attestation + provenance) |

> Semgrep is a **standalone, supervised plugin** that **augments** the CWE agent's
> deterministic skills + signatures — never merged in. Its CWE findings count toward the
> verified N only **after** passing the 0057 corpus gate. Test-first per CLAUDE.md.

## Checkpoints

### Phase 1 — Activation + routing
| # | Item | Tests | Status |
|---|------|-------|--------|
| 1a | Register + activate the bundled plugin (trust acks) | T1 | ☐ Not started |
| 1b | Route Semgrep into the scan phase of a CWE audit | T1 | ☐ Not started |
| 1c | Graceful absence — CWE audit runs skills+signatures if plugin down | T7 | ☐ Not started |
| **Gate** | Semgrep findings appear, still `candidate` (not in N) | T1, T7 | ☐ |

### Phase 2 — Taint mode + CWE attribution + pinning
| # | Item | Tests | Status |
|---|------|-------|--------|
| 2a | Enable taint-mode rulesets (dataflow) | T2 | ☐ Not started |
| 2b | CWE from `extra.metadata.cwe`; retire 2-entry map; `CWE-unknown` fallback | T3 | ☐ Not started |
| 2c | Pin Semgrep image + ruleset snapshot | T8 | ☐ Not started |

### Phase 3 — Augmentation (dedup / corroboration / provenance)
| # | Item | Tests | Status |
|---|------|-------|--------|
| 3a | Cross-agent corroboration/dedup (L3) — report once, boost on overlap | T4 | ☐ Not started |
| 3b | `provenance: semgrep` tag | T5 | ☐ Not started |
| **Gate** | Soak: confirm no double-reporting + measure FP profile before gating | T4, T5 | ☐ |

### Phase 4 — Corpus gating + attestation
| # | Item | Tests | Status |
|---|------|-------|--------|
| 4a | Corpus runner scores Semgrep CWEs; candidate→trusted promotion | T6 | ☐ Not started |
| 4b | `VERIFIED_CWES.md` gains the `semgrep` tier; N includes gated Semgrep CWEs | T9 | ☐ Not started |
| 4c | Coverage roadmap (skills → signatures → Semgrep → ~250–350) | — | ☐ Not started |

## Test ledger
| ID | Contract | Status |
|----|----------|--------|
| T1 | Semgrep activates + runs in a CWE scan | ☐ |
| T2 | taint mode finds a cross-line dataflow CWE skills miss | ☐ |
| T3 | CWE from metadata; unmapped → CWE-unknown, not dropped | ☐ |
| T4 | augment, no double-report (corroborate on overlap) | ☐ |
| T5 | provenance: semgrep tag | ☐ |
| T6 | Semgrep CWE gated (candidate→trusted) | ☐ |
| T7 | graceful without Semgrep (exit 0 + notice) | ☐ |
| T8 | Semgrep version + ruleset pinned | ☐ |
| T9 | attestation includes the semgrep tier; counts reconcile | ☐ |
| T10 | below-gate Semgrep CWE in DETECTED band, not in N | ☐ |

## Decisions log
- **Architecture (2026-06-26, per user):** Semgrep activated as a **standalone plugin** that
  **augments** the CWE deterministic skills — **not** merged into the CWE agent process
  (preserves process isolation + the LGPL-2.1 boundary).
- **Gated like signatures:** Semgrep CWEs count toward N only after passing the 0057 corpus
  gate (candidate→trusted).
- **§11.1 (2026-06-26):** on by default when available; graceful skills+signatures fallback.
- **§11.4 (2026-06-26):** skill↔Semgrep disagreements arbitrated by the **validation phase**
  (V6 voter + L3 + 0050 normalization), not static precedence; needs a cross-detector
  reconciliation step (P3 design item).
- **§11.2 (2026-06-27):** hybrid taint rulesets — upstream packs for breadth + Vulture-owned
  Apache-2.0 taint rules (pinned) for the guaranteed/counted CWEs.
- **§11.3 (2026-06-27):** strict + uniform gate (same as signatures); per-CWE `gates.yaml`
  overrides for documented exceptions; a separate "DETECTED (below-gate)" band that does not
  count toward N.
- **All §11 decisions resolved — 0058 review-complete.**

## Notes / blockers
- Depends on **0057 Phase 4–6** (corpus runner, gates, `VERIFIED_CWES.md`, provenance) being
  in place — 0058 Phase 4 extends them.
- Awaiting review sign-off on §11 (activation default, taint rulesets, gate parity,
  corroboration policy) before implementation.
