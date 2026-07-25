# Feature 0058 — Rollback Plan

| | |
|---|---|
| **Feature** | 0058_semgrep_cwe_augmentation |
| **Status** | 🟡 DRAFT |
| **Last updated** | 2026-06-26 |

## Blast radius

Semgrep runs as a **standalone, supervised plugin in its own container** — so rollback is
unusually clean: deactivating the plugin removes the entire tier without touching the CWE
agent. **No DB migration**; the corpus + attestation changes are additive (extend 0057's
files). The only third-party runtime is the Semgrep container image (LGPL-2.1, process-
isolated — no linkage). Because Semgrep is **augmentation, not a dependency** (R9), removing
it degrades coverage but never breaks a CWE audit.

## Kill switches (instant, no deploy)

| Action | Effect |
|---|---|
| **Deactivate the plugin** (registry) | CWE audits run skills + signatures only; the Semgrep tier disappears |
| `VULTURE_CWE_DISABLE_SEMGREP=true` | Skip Semgrep for CWE audits without deactivating the plugin globally |
| Per-audit `config.rule_packs` → drop taint packs | Fall back to pattern-only (lighter, less coverage) without disabling the tier |
| Stop the plugin container (supervisor) | Graceful absence path (R9) kicks in — audit proceeds with a "Semgrep tier not active" notice |

The graceful-absence design (R9) means *any* of these is safe at runtime — a missing/unhealthy
plugin never fails a CWE audit.

## Staged code rollback (highest-numbered phase first)

1. **Revert Phase 4 (gating/attestation)** — drop the `semgrep` tier from the corpus runner +
   `VERIFIED_CWES.md`. Semgrep findings still appear at runtime but stop counting toward N.
   Additive; safe to leave.
2. **Revert Phase 3 (augmentation)** — remove the cross-agent corroboration/provenance changes.
   Semgrep findings revert to plain separate-agent output (risk: overlap with skills could
   double-report — so prefer the kill switch over leaving Phase 3 half-reverted).
3. **Revert Phase 2 (taint/CWE/pin)** — restore pattern-only invocation + the prior CWE map.
   Semgrep behaves as it did pre-0058.
4. **Revert Phase 1 (activation/routing)** — deactivate + unroute the plugin. Back to the
   pre-0058 state: bundled-but-dormant Semgrep, CWE agent runs skills + signatures alone.

## Data considerations
- **None at the DB/schema level** — no migration.
- The Semgrep image + pinned ruleset are the only added runtime assets; removal is
  deactivation + image cleanup.
- `VERIFIED_CWES.md` is generated; regenerating after rollback simply drops the semgrep tier
  and recomputes N from skills + signatures.

## Verification after rollback
- A CWE audit produces no `provenance: semgrep` findings; no semgrep tier in `VERIFIED_CWES.md`.
- The plugin supervisor shows Semgrep inactive; CWE audits complete (skills + signatures),
  exit 0, with the "Semgrep tier not active" notice.
- `agents/cwe` + plugin test suites green.

## Trigger conditions
- Semgrep double-reporting against skills/signatures despite L3 corroboration (Phase 3 soak).
- Semgrep FP-rate on real audits exceeds the soak gate before/after promotion.
- Taint-mode performance/OOM on large repos beyond the resource caps.
- Ruleset drift changing N unexpectedly (re-pin or roll back the bump).

First response is always a **kill switch** (deactivate / `VULTURE_CWE_DISABLE_SEMGREP`), then a
staged code revert if the issue is structural. Because Semgrep is standalone + augmentation-
only, the kill switch is a complete, safe rollback on its own.
