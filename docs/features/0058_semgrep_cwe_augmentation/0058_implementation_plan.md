# Feature 0058 — Activate Semgrep as a Standalone Plugin Augmenting CWE Deterministic Coverage

| | |
|---|---|
| **Feature** | 0058_semgrep_cwe_augmentation |
| **Status** | 🟡 DRAFT — submitted for review (no code written) |
| **Date** | 2026-06-26 |
| **Depends on** | 0051–0053 (plugin registry / supervision / bundled Semgrep), 0057 (corpus harness + verified-coverage attestation + provenance) |
| **Source** | CWE coverage analysis (deterministic ceiling ~85/426 with skills+signatures; the taint-requiring slice needs a dataflow engine — already bundled) |

---

## 1. Goal

**Activate the bundled Semgrep plugin as a standalone, CWE-attributed, taint-enabled,
corpus-gated detection tier that *augments* the CWE agent's deterministic skills + signatures**
— extending deterministic CWE coverage to the dataflow/taint weaknesses regex structurally
cannot reach, **without** merging Semgrep into the CWE agent process (it stays a supervised,
container-isolated plugin — LGPL-safe).

Coverage intent: move deterministic CWE detection from ~85/426 toward the **~250–350 ceiling**
by adding the taint-requiring injection/validation/resource weaknesses Semgrep's dataflow
engine resolves. The corpus gate (0057) decides the real, provable increment.

## 2. Current state (grounded)

Vulture **already bundles** Semgrep (`plugins/semgrep/`, the 0053 reference plugin) running
under the 0051–0053 plugin architecture (registry, supervisor, stage-router). But it's a
fraction of its capability:

- **Taint mode is off.** It runs `semgrep scan --config p/security-audit` — pattern rules
  only (`plugins/semgrep/src/wrapper.py:105-128`). Semgrep's dataflow/taint engine is not
  engaged.
- **CWE attribution is near-empty.** `rules/rule_to_cwe.json` + `prefix_to_cwe.json` map **2
  CWEs total**; findings are barely CWE-tagged (`src/translate.py`).
- **Not gated, not counted.** Semgrep findings are a separate scan agent's output; they don't
  flow through the CWE verified-coverage attestation (`VERIFIED_CWES.md`, 0057) or the per-CWE
  corpus gate.
- **Activation/routing unfinished.** `plugin.toml` notes language pre-detection isn't shipped,
  so the router can't target Semgrep by language; the capability languages are empty ("any").

So this feature **enables + attributes + gates + activates** an engine that's already present
and supervised — integration, not engine-building.

## 3. Requirements

| ID | Requirement |
|---|---|
| **R1** | Semgrep runs as a **standalone plugin** (its own supervised container, per 0052/0053) — **never** linked or merged into the CWE agent process. Preserves the LGPL-2.1 process boundary. |
| **R2** | The plugin is **activated and invoked** within a CWE scan (registry activation + router routing), so its findings are part of the same audit as the CWE agent's skills + signatures. |
| **R3** | **Taint mode enabled** — Semgrep runs dataflow/taint rulesets (`mode: taint`, source→sink), not pattern rules alone. This is the capability that reaches the regex-unreachable CWEs. Rulesets are **hybrid**: curated upstream packs for breadth + **Vulture-authored Apache-2.0 taint rules** (vendored, pinned) for the guaranteed/counted CWEs. |
| **R4** | Findings are **CWE-attributed from Semgrep's own `extra.metadata.cwe`** (registry rules are CWE-tagged), replacing the 2-entry hand map. Unmapped findings are tagged `CWE-unknown`, never dropped silently. |
| **R5** *(AUGMENT, not duplicate)* | Where a Semgrep CWE overlaps a skill/signature finding (same CWE + file + line-window), the existing **cross-agent corroboration layer (L3, `stream_handler.go`)** corroborates (confidence boost) and reports **once**; Semgrep-only CWEs surface as **net-new** coverage. No double-reporting. |
| **R5b** *(CONFLICT → validate)* | When a skill and Semgrep **disagree** for the same site (severity / CWE-id / keep-or-demote), the **validation phase arbitrates** (V6 voter + L3 + 0050 CWE normalization) — no static precedence. Requires a cross-detector reconciliation step so taxonomically-related CWE-ids (e.g. CWE-22 ↔ CWE-73) are linked, not treated as two findings. |
| **R6** | Each finding carries a **`provenance: semgrep`** tag (extends 0057 P6b), so the attestation can attribute coverage per tier. |
| **R7** *(GATED)* | Semgrep-derived CWEs are **`candidate`** until they pass the 0057 per-CWE corpus gate (recall + precision), then **`trusted`** and counted toward the verified N. The gate is **strict + uniform** (same bar as signatures); justified exceptions use documented per-CWE `gates.yaml` overrides. CWEs that fire but miss the bar appear in a separate **DETECTED (below-gate)** band and do **not** count toward N. |
| **R8** | **Reproducibility** — the Semgrep binary version **and** the ruleset snapshot are **pinned** (like the CWE catalog 4.19.1 pin), so the deterministic tier + the gated N are stable run-to-run. |
| **R9** *(GRACEFUL)* | Semgrep is **augmentation, not a hard dependency** — if the plugin is not activated/available/healthy, the CWE audit still runs skills + signatures and reports it ran without the Semgrep tier (no failure, exit 0). |
| **R10** | **Bounded cost** — taint mode is heavier than pattern mode; the per-scan timeout, `--max-memory`, and vendored-dir excludes (`wrapper.py:46-55,116-124`) stay enforced; large-repo behavior is documented. |

## 4. Architecture

```
ONE CWE scan (orchestrator)
   ├─ CWE agent (Python, in-process):  skills (≈84) + signatures (0057) → deterministic findings
   └─ Semgrep plugin (standalone container, supervised):  taint + pattern rules
                                                            → CWE-attributed findings (metadata.cwe)
                          │                                              │
                          └───────────────┬──────────────────────────────┘
                                          ▼
        Cross-agent corroboration / dedup  (L3, stream_handler.go)
          · same CWE+file+line from a skill/signature AND Semgrep → corroborate, report ONCE
          · Semgrep-only CWE → net-new augmentation
                                          ▼
        V6 validation (L1/L2/L5) + provenance tag `semgrep`  →  high_confidence/suspicious/likely_fp
                                          ▼
        Corpus gate (0057): Semgrep CWEs candidate→trusted; counted in VERIFIED_CWES.md (semgrep tier)
```

**Standalone** = Semgrep keeps its own process/container, port, health/run endpoints, and
supervisor (0052) — no code linkage. **Augment** = its CWE findings join the same audit and
are corroborated/deduped against the deterministic skills/signatures, never replacing them.

If the plugin is inactive/unhealthy → the orchestrator proceeds with the CWE agent alone +
an explicit "Semgrep tier not active" note (R9).

## 5. Work items

Effort: S ≤1d · M 2–4d · L 1–2wk. Test-first per CLAUDE.md.

### Phase 1 — Activation + routing
| Item | What | Where | Effort |
|---|---|---|---|
| P1a | Register + **activate** the bundled plugin (trust acks `network-egress`/`host-network`); ensure the supervisor brings it up | `backend/pkg/pluginregistry/activation.go`, `plugins/semgrep/plugin.toml` | M |
| P1b | Route Semgrep into the **scan phase** of a CWE audit (capability matching; "any" until language sniffing) so its findings join the run | `backend/pkg/stagerouter`, `backend/internal/handler/stream_handler.go` | M |
| P1c | **Graceful absence** (R9): orchestrator proceeds with the CWE agent alone + a notice if the plugin is down | `stream_handler.go` | S |

### Phase 2 — Taint mode + CWE attribution + pinning
| Item | What | Where | Effort |
|---|---|---|---|
| P2a | Enable **taint-mode** rulesets (curated taint packs / `mode: taint` rules) alongside the security-audit pack | `plugins/semgrep/src/wrapper.py:105-128` | M |
| P2b | **CWE from `extra.metadata.cwe`** in the Semgrep JSON; retire the 2-entry map; `CWE-unknown` fallback | `plugins/semgrep/src/translate.py`, `rules/*.json` | S |
| P2c | **Pin** the Semgrep version (Dockerfile/image tag) **and** the ruleset snapshot; document the bump procedure (mirrors the catalog 4.19.1 pin) | `plugins/semgrep/Dockerfile`, `plugin.toml`, ruleset vendor dir | M |
| P2d | **Author Vulture-owned taint rules** (Apache-2.0, `mode: taint`) for the high-value guaranteed CWEs (SQLi / cmd-injection / path-traversal / SSRF / deserialization …); vendor + pin alongside the upstream packs (the hybrid set) | **add** `plugins/semgrep/rules/vulture/` | M |

### Phase 3 — Augmentation (dedup / corroboration / provenance)
| Item | What | Where | Effort |
|---|---|---|---|
| P3a | Cross-agent **corroboration/dedup** so Semgrep ↔ skills/signatures on the same CWE+file+line report once + boost (R5) | `backend/internal/handler/stream_handler.go` (L3), `backend/internal/cwe/layer*.go` | **L** |
| P3b | `provenance: semgrep` tag on Semgrep-sourced findings (extends 0057 P6b) | `translate.py` / aggregation | S |

### Phase 4 — Corpus gating + attestation
| Item | What | Where | Effort |
|---|---|---|---|
| P4a | Extend the 0057 corpus runner to score **Semgrep-derived CWEs** (per-CWE recall + precision) on the deterministic corpus; candidate→trusted promotion | `agents/cwe/tests/corpus/corpus_runner.py`, `scripts/promote_signatures.py` | M |
| P4b | `VERIFIED_CWES.md` gains a **`semgrep`** tier in the breakdown; N includes corpus-gated Semgrep CWEs; add a **DETECTED (below-gate)** band for Semgrep CWEs that fire but miss the strict gate (not counted in N) | `agents/cwe/tests/corpus/report_coverage.py` | S |
| P4c | Coverage-roadmap doc tying skills → signatures (0057) → Semgrep (0058) to the ~85 → ~250–350 trajectory | `docs/` | S |

## 6. Configuration

| Knob | Default | Notes |
|---|---|---|
| Plugin activation | **on by default when available** | graceful absence per R9; required acks granted at install |
| `rule_packs` (per-audit) | security-audit **+ taint packs** | operator-overridable (`wrapper.py:110`) |
| `VULTURE_CWE_DISABLE_SEMGREP` | — | escape hatch: CWE audit runs skills+signatures only |
| `max_memory_mb` / timeout | 2000 / 1500s | taint-mode cost bounds (R10) |
| Semgrep image + ruleset | **pinned** | reproducible N (R8) |

## 7. Test plan — test-first

- **T1 `test_semgrep_activates_in_cwe_scan`** — with the plugin healthy, a CWE scan includes Semgrep findings. (R2)
- **T2 `test_taint_finds_dataflow_cwe`** — a source→sink dataflow fixture (e.g. tainted input → SQL/command sink across lines) the skills miss is reported via the Semgrep taint tier. (R3 — the payoff)
- **T3 `test_cwe_from_metadata`** — Semgrep findings carry their `metadata.cwe`; an unmapped rule → `CWE-unknown`, not dropped. (R4)
- **T4 `test_augment_no_double_report`** — a CWE found by both a skill and Semgrep on the same line corroborates + reports once; a Semgrep-only CWE is net-new. (R5)
- **T5 `test_provenance_semgrep`** — Semgrep findings tagged `provenance: semgrep`. (R6)
- **T6 `test_semgrep_cwe_gated`** — a Semgrep CWE is `candidate` until its corpus fixtures pass, then `trusted` + counted in N. (R7)
- **T7 `test_graceful_without_semgrep`** — plugin down → CWE scan runs skills+signatures + a "Semgrep tier not active" notice, exit 0. (R9)
- **T8 `test_semgrep_version_pinned`** — the image/ruleset pin is asserted; an unpinned config fails the check. (R8)
- **T9 `test_attestation_includes_semgrep_tier`** — `VERIFIED_CWES.md` shows the semgrep tier; counts reconcile, no double-count vs skills/signatures. (R7/P4b)
- **T10 `test_below_gate_detected_band`** — a Semgrep CWE that fires but fails the strict gate appears in the **DETECTED (below-gate)** band and is **not** counted in N. (decision 3)

## 8. Rollout (soak → enforce)

1. **Phase 1** — activate + route; graceful absence; T1/T7. Semgrep findings appear but are
   `candidate` (not yet counted in N).
2. **Phase 2** — taint mode + CWE-from-metadata + pin; T2/T3/T8.
3. **Phase 3** — corroboration/dedup + provenance; T4/T5. **Soak**: confirm no double-reporting
   + measure FP profile on real audits before gating.
4. **Phase 4** — corpus-gate Semgrep CWEs + attestation tier; T6/T9. N grows by the gated
   Semgrep increment.

Gate each phase; Semgrep CWEs only count toward N after Phase 4.

## 9. Risks & mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | **Double-reporting** across skills/signatures/Semgrep | L3 cross-agent corroboration (R5/P3a); soak before gating; T4 |
| 2 | **Semgrep FP profile** (taint mode still over-reports) | findings land `candidate`; V6 + L5 demote; corpus precision gate before `trusted` (R7) |
| 3 | **Ruleset drift** changes N run-to-run | pin image + ruleset snapshot (R8/P2c); bump is a reviewed change |
| 4 | **Taint-mode performance/OOM** on large repos | `--max-memory`, timeout, vendored-dir excludes (R10); standalone container caps blast radius |
| 5 | **LGPL-2.1** | process/container isolation — no linkage (R1); already the plugin model; license rows exist |
| 6 | **Plugin not activated in some deploy modes** | graceful degradation (R9): CWE audit still runs skills+signatures + a notice |
| 7 | **Network/trust** (plugin requires egress/host-network acks) | in-tree trust tier; acks granted at install; documented |

## 10. Scope-lock — OUT

- **Merging Semgrep into the CWE agent process** — explicitly rejected (R1; standalone only).
- **Authoring a large custom taint-rule corpus** — start with curated upstream taint packs;
  bespoke rules are a follow-up.
- **Language sniffing engine** — use "any"/capability routing for now; full language
  pre-detection is its own item (noted in `plugin.toml`).
- **Non-CWE use of Semgrep** (e.g. its own audit type) — this feature scopes Semgrep to
  augmenting CWE coverage.

## 11. Open decisions — for review

1. **Activation default** — ✅ **decided (2026-06-26):** Semgrep is **on by default when
   available**; if the plugin is absent/unhealthy the CWE audit proceeds with skills +
   signatures (graceful, per R9).
2. **Taint rulesets** — ✅ **decided (2026-06-27):** **hybrid** — curated upstream taint
   packs for breadth (Phase 2), plus **Vulture-authored Apache-2.0 taint rules (vendored +
   pinned)** for the high-value CWEs guaranteed in N. The corpus gate filters both; only
   gate-passing CWEs count.
3. **Gate parity** — ✅ **decided (2026-06-27):** **strict + uniform** (same bar as the
   signatures: `min_recall=1.0/max_fp_rate=0.0/min_fixtures=3`). Documented per-CWE
   `gates.yaml` overrides for justified exceptions; Semgrep CWEs that fire but miss the bar
   appear in a separate **"DETECTED (below-gate)"** band in `VERIFIED_CWES.md` and do **not**
   count toward N.
4. **Conflict resolution** — ✅ **decided (2026-06-26):** when a skill and Semgrep disagree
   (severity / CWE-id / keep-or-demote) for the same site, the **validation phase decides** —
   the V6 voter + L3 cross-agent corroboration + 0050 CWE normalization arbitrate; **no
   static skill-vs-Semgrep precedence**. *Implication:* the validate phase needs a
   cross-detector reconciliation step so a skill's CWE-22 and Semgrep's CWE-73 on the same
   site are related via the CWE taxonomy rather than double-counted (tracked as a P3 item).

## 12. Acceptance criteria

- ☐ T1–T9 green; existing plugin + CWE + shared suites still green.
- ☐ Semgrep runs **standalone** (own container) and its CWE findings join a CWE scan.
- ☐ **Taint mode** reports ≥1 cross-line dataflow CWE the skills miss (T2).
- ☐ No double-reporting across skills/signatures/Semgrep (T4); Semgrep-only CWEs are net-new.
- ☐ Semgrep CWEs are corpus-gated (candidate→trusted) and appear as a tier in `VERIFIED_CWES.md`.
- ☐ Semgrep version + ruleset pinned; N reproducible.
- ☐ Plugin down → CWE audit still runs skills+signatures, exit 0.
- ☐ Coverage roadmap documents the skills → signatures → Semgrep trajectory toward ~250–350.
