# Feature 0058 — Implementation Status

| | |
|---|---|
| **Feature** | 0058_semgrep_cwe_augmentation |
| **Status** | 🟡 PARTIAL — the bundled Semgrep plugin (feature 0053 + 0055 hardening) exists and runs when the `semgrep` audit type is explicitly selected. **0058-specific work (R2 auto-activation in CWE scans, R3 taint rulesets, R6 provenance, R7 corpus gating, R5b CWE-taxonomy reconcile) is NOT done.** A 2026-07-03 audit fixed several pre-existing defects (below). |
| **Last updated** | 2026-07-03 |

> **⚠️ Correction (2026-07-03):** the prior "No code written" was wrong — the
> 0053 reference plugin + a ~50-entry `rule_to_cwe.json` already shipped. The
> plan §2 "current state (2 CWEs, near-empty)" is likewise stale.

## Audit fixes applied (2026-07-03) — test-first, all green (43 plugin unit tests)
- **H2/S1 (security):** `config.rule_packs` now allowlisted to pinned `p/<name>` registry packs — URLs / local paths / `auto` rejected (was an SSRF / arbitrary-`--config` sink; audit config is client-controlled). `max_memory_mb` clamped to [256, 4000]. (`wrapper.py`)
- **C1 (correctness):** Semgrep paths normalized to **repo-relative** (strip scan-root prefix, idempotent) so they match the in-tree agents' paths in the cross-agent dedup key — closes the guaranteed double-reporting that defeated the augment-not-duplicate goal. (`translate.py`)
- **C4 (correctness):** severity read from `extra.severity` with a top-level fallback (defensive against schema drift). (`translate.py`)
- **H1 (partial):** `--pro` engine enabled when `SEMGREP_APP_TOKEN` is set (interprocedural taint); OSS still runs intraprocedural taint from the security packs. Dedicated vendored taint rulesets (R3/P2d) remain TODO. (`wrapper.py`)
- **L2:** `--` terminator before `source_path`. **L3:** memory clamp (above). **REL1:** hostile/malformed `config` can no longer crash argv-building mid-stream. **L4:** `tools/` test import fixed (collects standalone). **C2:** manifest `emits` corrected to the actually-emitted event set. **C3:** removed dead `rules/prefix_to_cwe.json`. **S4:** README network section corrected (host network + egress, not "internal").

## Audit fixes — round 2 (2026-07-03, backend + provenance)
- **R6 (provenance):** Semgrep findings now carry `provenance: "semgrep"` (verified it flows through the backend model → DB). Enables UI/gating to flag them as un-gated. (`translate.py`)
- **S2 (HIGH security — FIXED in code):** the supervisor now injects `VULTURE_BIND_HOST=127.0.0.1` for **host-network** plugins, and the plugin `Dockerfile` binds `${VULTURE_BIND_HOST:-0.0.0.0}` — so `/run` binds **loopback** (backend reaches it via localhost) instead of every host interface. Non-host/compose plugins keep 0.0.0.0. (`backend/internal/pluginsupervisor/argv.go` + `plugins/semgrep/Dockerfile`; Go tests green.) **NB: takes effect on the next `vulture-plugin-semgrep` image rebuild.**
- **C1/C4 VERIFIED** against real semgrep 1.168.0: semgrep returns **absolute** paths for an absolute target (C1 fix confirmed necessary); severity is under **`extra.severity`** (C4 was a false alarm — original was correct; the added top-level fallback is harmless).
- **S3 (downgraded):** the local-mode host-`/` RO mount (`argv.go` buildFSArgs) remains, but with S2's loopback bind it is **no longer LAN-exploitable** — now a localhost-only defence-in-depth gap. Properly scoping it (stage sources, or a configurable `VULTURE_SCAN_ROOT` instead of `/`) is a local-mode design change — see below.

## Still OPEN (require scoped work / product decisions — NOT bug fixes)
- **R2** — ⚠️ **scope corrected (2026-07-03): auto-activation is REJECTED.** Semgrep runs only when the **user ticks the `semgrep` audit type** (and the plugin is registered/activated/healthy) — never forced, never auto-activated inside a bare `cwe` scan. Today's behavior (runs when `semgrep` is explicitly selected; `stagerouter/scanagents.go` correctly skips auto-adding in-tree plugins) is therefore **already the desired trigger** — no router change needed. The real R2 work is making the ticked Semgrep's findings **augment** the CWE agent's in the shared audit (R5b reconcile + R6/R7 provenance/gating), not activation.
- **R3** — vendored taint rulesets + pinning (`rules/vulture/`).
- **R6/R7/R5b** — `provenance: semgrep` tag, corpus gating (candidate→trusted, below-gate band, `VERIFIED_CWES.md` semgrep tier), CWE-taxonomy reconciliation.
- **S2 (HIGH, backend security)** — `/run` is unauthenticated on the host network (loopback-bound after the S2 fix, but still unauthenticated); a design decision on auth remains.
- **S3 (backend)** — local mode mounts host `/` at `/audit-inputs`, making `normalise_source_path`'s guard a no-op there. **Design now decided (2026-07-03):** fix by adopting the existing staging pattern — mount `AuditsDir` not `/`, stage source per audit (git-clone-in-place + excluded local-dir copy), reap + disk/concurrency guards; ephemeral per-audit containers rejected. Specced in the LLD as **R11 / §4a / Phase 0 (P0a–P0d) / T11–T12**. Ready to implement (test-first); not yet coded.
- **R8** — pin the Semgrep image (mutable `:0.1.0` tag) + ruleset snapshot so gated N is reproducible.
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

## Design note — L5 LLM judge does NOT gate Semgrep/plugin findings (by design, 2026-07-03)

Recorded so the absence of an L5 pass on Semgrep findings is not later mistaken for a
missing feature.

**Two-tier gating — L5 is only for the LLM tier:**
- **Deterministic detectors** (the agents' regex skills, the 0057 signature tier, and
  **Semgrep's pattern/taint rules**) are gated on **precision/recall against the labeled
  corpus** (0057 gate; Semgrep's is **R7**). That corpus gate is their quality control.
- **LLM-*generated* findings** (non-deterministic, speculative) are gated by the **L5
  exploitability judge** (`shared/validate/llm_judge.py`, generate-then-verify).

**Why L5 does nothing for Semgrep as-is (verified):**
1. **It never reaches L5.** L5 lives in the Python `audit_runner` validate phase, which runs
   *inside each in-tree agent process*. Semgrep is a **standalone plugin container** — its
   `wrapper.py` only translates + streams; it bypasses `audit_runner` entirely. On the
   backend, plugin findings get only the **L3 cross-agent corroboration boost**
   (`applyCrossAgentValidation` in `stream_handler.go`), never an L5 pass.
2. **Even if routed to L5, it is exempt.** `_is_deterministic` / `_is_l5_exempt` treat a
   finding with a `check_id` and `provenance != "llm"` as deterministic-authoritative → the
   judge **cannot demote it**. Semgrep findings carry a `check_id` + `provenance:"semgrep"`
   (R6), so L5 would pass them through untouched.

**So L5 must NOT be required for every plugin/agent at each phase:**
- It would be **wasted work** on tiers it is forbidden to act on (deterministic ⇒ exempt).
- It does not scale in **cost/latency** — per-finding LLM calls × every detector × every
  phase, re-judging the same overlapping findings.
- It breaks the **plugin model** — plugins are process/language-isolated (Go/Node/Rust are
  valid plugin languages); each cannot embed the Python judge + its CancelToken/RC6
  safeguards.

**If uniform validation is ever wanted:** do it as **one centralized, opt-in,
provenance-aware validate pass in the orchestrator** over the aggregate deduped finding set
(natural home: the existing backend `deduplicateCrossAgent` step) — *not* L5 embedded in
each plugin/agent/phase. Such a pass would skip deterministic provenance and judge only the
LLM tier.

**Consequence for 0058:** Semgrep's correct quality control is **R7 corpus gating** (+ L3
corroboration), not L5. The R5b "validation phase arbitrates skill↔Semgrep disagreements"
(decisions log §11.4) refers to the **V6 voter + L3 + 0050 normalization**, *not* L5 — and
even that arbitration is currently partial: `crossAgentKey` matches exact
`(category, file, line)`, so taxonomically-related CWE-ids at one site (e.g. CWE-22 ↔
CWE-73) are not yet linked (the R5b cross-detector reconciliation step remains TODO, above).

## Notes / blockers
- Depends on **0057 Phase 4–6** (corpus runner, gates, `VERIFIED_CWES.md`, provenance) being
  in place — 0058 Phase 4 extends them.
- Awaiting review sign-off on §11 (activation default, taint rulesets, gate parity,
  corroboration policy) before implementation.
