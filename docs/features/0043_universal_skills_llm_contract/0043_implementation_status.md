# 0043 — Implementation Status

**Branch**: tbd (recommend `feat/0043-universal-skills-llm-contract`)
**Status**: SHIPPED v1.0 + v1.1-lite (Phase 1 helper + Phase 3 prove fix + Phase 4 discover refactor + Phase 5-lite degraded_mode emitter)
**Owner**: tbd
**Created**: 2026-05-02
**v1.0 ship date**: 2026-05-02 (Phases 1+3 minimal fix — stops the cooldown regression)
**v1.1-lite ship date**: 2026-05-02 (Phase 4 discover compliance + Phase 5-lite emitter)
**Target v1.2** (Phase 5 full — per-finding analysis_mode field + DB migration + frontend label): +1 day
**Target v1.3** (Phases 6+7 — CI purity test + docs): +1 day
**Target v1.4** (Phase 8 — default-on cutover): after ~1-week stability window

## v1.1-lite ship summary (Phases 4 + 5 lite)

Discover agent compliance turned out to be a 5-line refactor —
`LLMEndpointPlugin.accepts()` already gated on `VULTURE_USE_LLM=true`
(verified by reading `discover_agent/plugins/llm_suggest.py:59-70`).
v1.1 routes that read through the shared `is_skills_only()` helper
for consistency and adds 6 unit tests asserting the gate behavior.

Phase 5-lite ships the `degraded_mode` SSE event emitter helper in
`shared/transport/event_emitter.py` — the per-finding `analysis_mode`
field + DB migration is deferred to v1.2 because it touches more
layers (Go model, repos, Postgres + SQLite migrations, frontend
type, UI label).

What lands in v1.1-lite:

- `discover_agent/plugins/llm_suggest.py::accepts()` — refactored to
  use `shared.llm.mode.is_skills_only()`; provider-key check stays as
  defense-in-depth so USE_LLM=true without any key still skips the
  plugin (avoids fresh AuthenticationError surface).
- `discover/tests/unit/test_skills_only_mode.py` — 6 tests covering
  the (USE_LLM × provider-key) matrix.
- `shared/transport/event_emitter.py::degraded_mode()` — new emitter
  method producing a `degraded_mode` SSE event with `audit_mode` tag.
- `shared/tests/unit/transport/test_degraded_mode_event.py` — 5
  tests covering the canonical shape, default `audit_mode`, and the
  three explicit modes (`degraded`/`skills_only`/`required_failed`).

## v1.0 ship summary (Phases 1 + 3)

The minimum-viable fix for the prove cooldown regression. Ships:

- `agents/shared/shared/llm/mode.py` with `is_skills_only()` and
  `is_llm_required()` synchronous helpers (Phase 1).
- `agents/shared/tests/unit/llm/test_mode.py` with 11 tests covering
  the env-var grammar (unset / empty / "false" / "true" / case
  variants).
- `prove_agent/agent.py::run_prove` short-circuits when
  `is_skills_only()` returns True. The short-circuit happens BEFORE
  any LLM machinery is touched (`reset_token_usage`, `get_model`),
  so no AuthenticationError + cooldown loops are possible.
- `prove_agent/tests/unit/test_skills_only_mode.py` with 5 tests
  asserting: unset / explicit-false skip cleanly; LLM helpers are
  never imported in skills mode; `VULTURE_REQUIRE_LLM=true` +
  skills-only is a config conflict (fails loudly); `VULTURE_USE_LLM=true`
  does not short-circuit (preserves existing LLM-mode path).

What's deliberately deferred to v1.1:

- The async `resolve_audit_mode()` 4-state enum from the plan — v1.0
  only needs the synchronous skip path; the LLM-health probe is only
  useful when the agent has a "degraded" fallback to run, which prove
  doesn't have until v1.1+ when rule-based verification ships.
- Discover agent gating (Phase 4).
- Per-finding `analysis_mode` field + DB migration (Phase 5).
- CI purity test (Phase 6).

## Phase summary

| Phase | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| 1 — Contract definition + `shared/llm/mode.py` | PLANNED | — | v1.0 | Single helper, single doc, foundation for every other phase |
| 2 — Audit scan-agent compliance | PLANNED | — | v1.0 | Verify the 8 scan agents are already-compliant via `run_combined_audit()` |
| 3 — Prove agent rewrite (skills-mode path) | PLANNED | — | v1.0 | The urgent fix; uses existing `strategies/` modules as skills path |
| 4 — Discover agent gating | PLANNED | — | v1.1 | Plugin-only mode + LLM endpoint suggestion gated |
| 5 — `degraded_mode` SSE event + `analysis_mode` field | PLANNED | — | v1.1 | DB migration `015_finding_analysis_mode.sql` |
| 6 — CI test for skills-mode purity | PLANNED | — | v1.2 | Mock LLM endpoint; fail on any request; grep logs for AuthenticationError |
| 7 — Documentation + per-agent CLAUDE.md | PLANNED | — | v1.2 | One section per agent; operator-facing notes |
| 8 — Default-on rollout (remove feature flags) | PLANNED | — | v1.3 | After ~1 week of CI green |

## Detailed task list

### Phase 1 — Contract + helper

- [ ] 1.1.t1 — Write `docs/architecture/agent_llm_contract.md` (~200 lines)
- [ ] 1.1.t2 — Implement `agents/shared/shared/llm/mode.py` with
      `AuditMode` enum, `ModeDecision` namedtuple, `is_skills_only()`,
      `is_required()`, `resolve_audit_mode()`
- [ ] 1.1.t3 — Unit tests in `agents/shared/tests/unit/llm/test_mode.py`
      (5 tests covering the `(USE_LLM × REQUIRE_LLM × reachable)` matrix)

### Phase 2 — Scan-agent compliance audit

- [ ] 2.1.t1 — Per-agent smoke: `VULTURE_USE_LLM=false python -m
      <agent>.main` against a tiny corpus; mock litellm; assert no calls
- [ ] 2.1.t2 — Document findings in §Audit results (below) for each agent
- [ ] 2.1.t3 — Local fix for any non-compliant agent

### Phase 3 — Prove rewrite

- [ ] 3.1.t1 — Inventory all LLM call sites in `prove_agent/`
- [ ] 3.1.t2 — Build `prove_agent/runners/rule_based.py` wrapping
      existing `strategies/` modules
- [ ] 3.1.t3 — Refactor `prove_agent/agent.py::run_prove` to branch on
      `resolve_audit_mode()`
- [ ] 3.1.t4 — Inconclusive findings get explicit `status` + `reason`
- [ ] 3.1.t5 — Tests:
      - `test_prove_skills_only_no_llm`
      - `test_prove_uncovered_finding_marked_inconclusive`
      - `test_prove_required_failed_aborts`
      - `test_prove_degraded_emits_banner_once`
- [ ] 3.1.t6 — Update `agents/prove/CLAUDE.md`: skills/LLM mode section

### Phase 4 — Discover gating

- [ ] 4.1.t1 — Inventory LLM call sites in `discover_agent/`
- [ ] 4.1.t2 — Refactor `discover_agent/agent.py::run_discover` to
      branch on `resolve_audit_mode()`; gate LLM endpoint suggestion
- [ ] 4.1.t3 — Tests: skills-only plugin path, LLM-augmented path

### Phase 5 — SSE event + analysis_mode field

- [ ] 5.1.t1 — Add `degraded_mode` event to
      `agents/shared/shared/transport/event_emitter.py`
- [ ] 5.1.t2 — Verify backend `agui/translator.go` passes through
      cleanly; add explicit case if needed
- [ ] 5.1.t3 — Add `analysis_mode` to `model.Finding` (Go) +
      Postgres/SQLite repos + emitted finding events (Python)
- [ ] 5.1.t4 — DB migration `015_finding_analysis_mode.sql`
      (additive `ALTER TABLE`)
- [ ] 5.1.t5 — Frontend `Finding` type + audit-results UI label
- [ ] 5.1.t6 — Same for `prove_results.analysis_mode`

### Phase 6 — CI test

- [ ] 6.1.t1 — `.github/workflows/skills-mode-purity.yml` — start
      stack with `VULTURE_USE_LLM=false`, mock LLM HTTP endpoint
      that fails on any request, run a tiny audit, assert no LLM
      requests + no AuthenticationError + no `model_cooldown_start`
      in logs
- [ ] 6.1.t2 — Run on every PR + push to main/master

### Phase 7 — Documentation

- [ ] 7.1.t1 — Update each agent's `CLAUDE.md` with skills/LLM section
- [ ] 7.1.t2 — Update `docs/architecture/agent_protocol.md` with
      `degraded_mode` event + `analysis_mode` field
- [ ] 7.1.t3 — Update `docs/guides/cli_usage.md`

### Phase 8 — Default-on cutover

- [ ] 8.1.t1 — Remove `VULTURE_PROVE_SKILLS_MODE` feature flag
- [ ] 8.1.t2 — Remove discover feature flag if any
- [ ] 8.1.t3 — Update status doc

## Cross-cutting

- [ ] CC.1 — All new functions have cyclomatic complexity < 10
- [ ] CC.2 — `ruff check` clean across new code
- [ ] CC.3 — `pytest --cov` ≥ 100% on `shared/llm/mode.py` and the new
      prove rule-based runner
- [ ] CC.4 — No regression in existing scan-agent test suites
- [ ] CC.5 — `degraded_mode` event renders in the existing frontend
      banner without frontend code changes (feature 0039's banner is
      generic enough)
- [ ] CC.6 — CI test (Phase 6) is reliably green for ≥ 1 week before
      Phase 8 default-on cutover

## Audit results (Phase 2 — to fill in during implementation)

(Initially empty. Per-agent compliance check fills this table.)

| Agent | Calls `run_combined_audit`? | Direct LLM call sites outside? | Status |
|---|---|---|---|
| chaos_engineering | ✓ | TBD | TBD |
| owasp | ✓ | TBD | TBD |
| soc2 | ✓ | TBD | TBD |
| cwe | ✓ | TBD | TBD |
| xss | ✓ | TBD | TBD |
| ssdf | ✓ | TBD | TBD |
| do178c | ✓ | TBD | TBD |
| asvs | ✓ | TBD | TBD |
| discover | ✗ | ≥ 1 (LLM endpoint suggestion) | NON-COMPLIANT — Phase 4 |
| prove | ✗ | ≥ 1 (per-finding LLM verification) | NON-COMPLIANT — Phase 3 |

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-05-02 | Single shared helper `shared/llm/mode.py` is the only authoritative source for the env-var read. Every agent calls through it. No agent reads `VULTURE_USE_LLM` directly after this feature lands. | spec |
| 2026-05-02 | Skills-mode prove returns `inconclusive` for rule-uncovered findings rather than failing the audit. Inconclusive is a distinct status from `not_exploitable`; UI uses three icons (verified / not-exploitable / inconclusive). | spec |
| 2026-05-02 | `analysis_mode` is a per-finding field, not a per-audit field. A single audit can mix modes (some findings rule-verified, others LLM-verified) when the operator runs in `SKILLS_PLUS_LLM` and prove uses both paths. | spec |
| 2026-05-02 | Migration `015` is additive `ADD COLUMN IF NOT EXISTS analysis_mode TEXT NOT NULL DEFAULT 'skills_plus_llm'`. Legacy rows default to `skills_plus_llm` (the pre-0043 implicit mode) — operators can filter on this for cohort analysis. | spec |
| 2026-05-02 | `VULTURE_REQUIRE_LLM=true` from feature 0039 is the operator's lever for "I genuinely need LLM, fail fast if it's down." Adds `REQUIRED_FAILED` mode, distinct from `DEGRADED`. | spec |
| 2026-05-02 | Phase 8 (default-on cutover) gates on Phase 6 CI green for ≥ 1 week. Avoids forcing the new behavior before we have stability data. | spec |
| TBD | Should `--llm-mode` CLI flag plumb to per-audit override? | |
| TBD | Should there be a `vulture audit modes` subcommand showing the matrix at a glance? | |

## Out of scope (tracked separately)

- Per-CLI-flag mode override (`--llm-mode skills|llm|auto`)
- Tiered LLM use (cheap model for some findings, expensive for others)
- LLM-only prove fallback when rules cover but produce low-confidence verdict
- Skills coverage report (per-category "% findings rule-verifiable")
- OpenAI Agents SDK loop_guard interaction
- Backfilling legacy `analysis_mode` based on historical env config

## Planned follow-ups

- v1.4 if needed: per-CLI-flag mode override (`vulture scan --llm-mode auto`)
- v1.5 if demanded: skills coverage telemetry surfaced in the operator UI
