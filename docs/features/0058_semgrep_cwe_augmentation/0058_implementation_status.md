# Feature 0058 — Implementation Status

| | |
|---|---|
| **Feature** | 0058_semgrep_cwe_augmentation |
| **Status** | 🟢 IMPLEMENTED (TDD, RED→GREEN) + E2E-verified on a live stack (LM Studio `qwen/qwen3.6-27b` + Postgres). R3 taint (vendored Apache-2.0 rules), R4 CWE attribution (`CWE-unknown` fallback), R5b CWE-taxonomy reconcile, R6 provenance, R7 corpus-gate semgrep tier, R11/S3 per-audit staging (no host-`/` mount) + frontend provenance chips/filter + graceful-tier notice all landed. Unit/integration suites green (backend 23 pkgs, 590 CWE, 66 plugin, 341 frontend). Three defects found+fixed during E2E (below). **Outstanding: independent 10-dimension review panel could not complete (session-limit); webkit Playwright blocked on host libs.** |
| **Last updated** | 2026-07-05 |

## Implementation + E2E verification (2026-07-04/05)

**Landed (test-first):** `backend/internal/staging/` (Stage/Reap/Sweep/HasCapacity — symlink-safe, SKIP_DIRS + gitignore-subset, disk-budget + concurrency cap), `argv.go` (local mode mounts `AuditsDir`, never host `/`), `stream_service.go` (containerStager staging wiring + `agentUnavailableEvent` R9 notice), `internal/cwe/taxonomy.go` + `handler/cwe_taxonomy.go` (`canonicalCWEGroup` family reconcile), plugin `wrapper.py`/`translate.py` (vendored taint rules, `cwe` key, provenance, snapshot pin), corpus `score_semgrep_corpus`/attestation tier, frontend `shared/Chip.tsx` + `ProvenanceChip`/`SemgrepTierNotice`/provenance filter + 6-locale i18n.

**Three defects found & fixed during live E2E** (would not surface in unit tests):
1. **`--project-root` version skew (CRITICAL)** — the plugin passed `--project-root`, valid in host semgrep 1.168.0 (where tests ran) but NOT in the pinned image 1.84.0 → `semgrep scan` errored → **every audit's semgrep phase silently returned 0 findings**. Removed (redundant under staging: the target is an isolated per-audit tree). Regression test `test_argv_version_compat.py` pins its absence.
2. **Notice phrase case mismatch** — backend emits `"semgrep tier not active …"` (lowercase agentType) but `SemgrepTierNotice` matched `"Semgrep tier not active"` case-sensitively → notice never showed in production. Fixed to case-insensitive match.
3. **Playwright notice-mock greedy glob** — the spec's `**/stream*` route shadowed `/stream-token` (last-registered wins), 500-ing the token fetch so EventSource never opened. Tightened the mock glob to the SSE endpoint only (assertion unchanged).

**Verification matrix:**
| Check | Result |
|---|---|
| Vendored taint rule fires (flask→`os.system`, hermetic, no network) | ✅ CWE-78 |
| Finding persisted with `provenance=semgrep` + `category=CWE-78` | ✅ |
| S3: container mounts `AuditsDir` (not `/`), loopback bind, staged tree scanned | ✅ |
| Direct semgrep vs audit-path parity | ✅ audit ⊇ direct (vendored + `p/security-audit`) |
| Playwright chips/filter/notice — chromium + firefox | ✅ 6/6 |
| Playwright webkit (Safari) | ⚠️ blocked — host libs need root (config present; runs in CI) |
| Multi-OS staging/pluginsupervisor/handler binaries — Ubuntu 24.04 / Fedora 41 / Kali rolling | ✅ all pass |
| 10-dimension review panel | ⏳ not run — session-limit (resets); re-run pending |

**Reliability note (resolved):** `p/security-audit` (registry) is re-fetched per run and cannot be cached offline — the tests pin the registry alias, and Semgrep persists no rule cache — so it needs egress at scan time (a granted `runtime.network` capability). The **vendored `rules/vulture/` taint rules are the hermetic guaranteed tier** (work offline). Crucially, a registry-fetch failure is now **surfaced as an audit error** (not a silent 0 — see the review HIGH fix below), so degraded coverage is visible.

## Review round (2026-07-05) — 10 adversarially-confirmed findings, fixed

The 10-dimension review panel (re-run leaner after two session-limit aborts) surfaced 10 confirmed findings; the code bugs are fixed and guarded:

- **HIGH — errored scan swallowed as clean 0-findings** (`agui/translator.go`): a `result` payload carrying `error` was dropped by `parseSnapshot` (reads only `{findings,score}`) → an errored/timed-out/mis-flagged scan looked identical to a clean one (the root reason `--project-root` was invisible). Fixed: `translateResult` now emits an `ERROR: …` text event so `collectErrorText` marks `AgentError`. Regression test `translator_result_error_test.go`.
- **HIGH — plugin nonzero-exit → error (untested bug class)**: added `test_exit_error_not_silent.py` pinning `_classify_exit`.
- **MED — staging walk→copy TOCTOU**: `copyFile` now opens `O_NOFOLLOW` (a post-walk symlink swap fails closed instead of dereferencing host bytes). Test `TestCopyFile_RefusesSymlink`.
- **MED — `agentUnavailableEvent` bare send could deadlock `wg.Wait`** → staged-tree leak: send now `select`s on `ctx.Done()`.
- **MED — staging ignored `VULTURE_IGNORE_GITIGNORE`**: `loadIgnores` now honors it (matching `file_scanner`). Test `TestStage_HonorsIgnoreGitignoreFlag`.
- **MED — untested capacity-refusal / ctx-cancel**: added `TestStage_HonorsContextCancellation` (+ capacity covered via `HasCapacity`).
- **LOW — sibling-audit symlink reachability & router-fallback coverage**: documented in `copySymlink` (accepted: local-mode single-tenant, discloses only other scanned source).

**Also fixed (found via full-suite + E2E, same round):**
- **`--project-root` is now VERSION-CONDITIONAL** (`wrapper.py`): the pinned image Semgrep 1.84.0 rejects the flag (→ 0 findings); newer host Semgrep needs it so the default `.semgrepignore` (`tests/`) doesn't skip audited files. A cached, fail-safe capability probe includes it only where supported (container→omit, host→include). Test `test_argv_version_compat.py`.
- **`HOME` handling**: removed the redundant `ENV HOME=/tmp` from the Dockerfile (the supervisor injects `-e HOME=/tmp`; a root-run build pre-warm under it created a root-owned `/tmp/.semgrep` unwritable by the runtime user).

**Differential accuracy guard added** (answering "compare against standalone CLI"): `test_cli_parity.py` runs a standalone `semgrep` CLI as ground truth and asserts the plugin's `translate_findings` path matches it 1:1 on `(cwe, file, line)` — catches translation drift, dropped findings, and argv regressions.

Suites after this round: **backend 23 pkgs 0-fail · plugin 72 · frontend 341 · Playwright chromium+firefox 6/6**.

## Semgrep version bump — R8 (2026-07-05): 1.84.0 → 1.168.0 (latest stable)

Bumped the pinned engine to the latest stable (>1.76.0) via the R8 procedure (version + ruleset snapshot pinned together):
- `Dockerfile` `FROM semgrep/semgrep:1.168.0@sha256:59fbed6127ea…` (new digest; LGPL-2.1 re-noted).
- `Dockerfile` pin `semgrep==1.168.0` — the 1.168.0 base is a **PEP 668 externally-managed** Python env, so the pin now carries `--break-system-packages` (resolves as "already satisfied" — a no-op assertion that fails loudly on base drift; the 1.84.0 base didn't need it).
- `rules/RULESET_SNAPSHOT.json` gains `"semgrep_version": "1.168.0"`; vendored rule hashes recomputed (unchanged).

Also added standard **build-artifact excludes** across all three layers (plugin `_SCAN_EXCLUDES`, backend `staging.skipDirs`, in-tree `file_scanner.SKIP_DIRS`): `storybook-static`, `.output`, `.svelte-kit`, `.angular`, `.docusaurus`, `.turbo`, `.parcel-cache`, `.cache`, `coverage`, `.nyc_output` — an idattestor comparison showed 5 of 6 findings were in generated/minified bundles, not source. `.vultureignore` remains the per-project escape hatch for non-standard artifact dirs (e.g. idattestor's `.next-e2e`), and it flows to the plugin via staging.

**Effect:** the plugin (1.168.0) now matches the host CLI version exactly — closes the version-skew gap; `--project-root` is supported in-container. T8 pinning + full plugin suite (72) green on the new pin.

## Solidity coverage via the semgrep plugin (2026-07-07)

The semgrep plugin does its own file discovery over the staged tree, so it scans `.sol` files even though the in-tree agents' `file_scanner.CODE_EXTENSIONS` doesn't list `.sol` (that gap only affects the Python skill agents, not the plugin). Two Solidity tiers added — mirroring the Python/JS hybrid model:

- **Vendored, pinned, HERMETIC tier** — `plugins/semgrep/rules/vulture/solidity/vulture-solidity.yaml` (Apache-2.0): `tx.origin`-auth (CWE-284), unprotected `selfdestruct` (CWE-284), untrusted `delegatecall` (CWE-829). Auto-loaded via the existing `--config <vendored-dir>` (recursive), pinned in `RULESET_SNAPSHOT.json` (`solidity/…` relpath), always on, no network. Verified firing on semgrep 1.168.0 (3/3, correct CWEs, `provenance=semgrep`).
- **Registry breadth tier — `r/solidity`** (the real Semgrep Solidity namespace; **there is no `p/solidity` — it 404s**). Wired as an **operator default** (`_solidity_registry_config`, default-set only, not client-injectable → no widening of the H2 client allowlist), egress-required, **disable** via `VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY`. Best-effort/experimental + unversioned (drift) — the vendored tier is the guaranteed one.

Tests: `tests/e2e/test_solidity.py` (registry wiring: present by default / absent when `rule_packs` pinned / absent when disabled; vendored rules shipped + detect on a `.sol` fixture). Full plugin suite **77 green**; hermetic taint e2e unaffected. **Caveat:** this is pattern-level Solidity — not a substitute for Slither/Mythril dataflow/symbolic analysis; and corpus-gating Solidity CWEs toward N (R7) is a follow-up.

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
