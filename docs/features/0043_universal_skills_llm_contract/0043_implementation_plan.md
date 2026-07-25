# 0043 — Universal skills/LLM dual-mode agent contract

**Author**: tbd
**Status**: PLANNED
**Created**: 2026-05-02

## Problem

Tonight (2026-05-02), running `./scripts/vulture.sh dev skills` — which is
documented as "skills only — no LLM (fastest, no API key needed)" — produced
this error stream from the `agent-prove` process every 5 minutes for hours:

```
[agent-prove] LLM call failed (attempt 1): litellm.AuthenticationError:
  AuthenticationError: OpenAIException - The api_key client option must be
  set either by passing api_key to the client or by setting the
  OPENAI_API_KEY environment variable
[agent-prove] model_cooldown_start model=gpt-4o failures=53 cooldown=300s
```

`scripts/start.sh:185` correctly exports `VULTURE_USE_LLM=false` for the
`skills` provider. The 8 scan-phase agents (chaos / owasp / soc2 / cwe /
xss / ssdf / do178c / asvs) honor this env var because they all delegate
to `shared/audit_runner.py::run_combined_audit()`, which gates the LLM
phase on `VULTURE_USE_LLM == "true"`. The 2 pipeline agents — **prove**
and **discover** — do not. Searching the codebase:

```
$ grep -rn VULTURE_USE_LLM agents/prove/ agents/discover/
(no matches)
```

Both agents call LLMs unconditionally. In skills-only deployments — the
documented entry-level mode that "needs no API key" — they hammer the LLM
endpoint with no key, accumulate cooldown failures, spam the operator's
logs, and never produce useful output.

The deeper issue is **there is no contract** for how an audit-producing
agent must behave when `VULTURE_USE_LLM` is false. Each agent author
makes their own decision. Some agents (scan-phase) decided correctly via
`run_combined_audit()`; others (prove, discover) decided "always require
LLM." Prospectively, the next agent someone writes will face the same
choice with no guidance.

## Goals

1. **Define the contract once.** Every audit-producing agent
   (`agents/<name>/<name>_agent/`) MUST honor `VULTURE_USE_LLM=false` and
   produce useful output without an LLM call, or exit cleanly with a
   degraded-mode banner. No silent cooldown loops. No keyless LLM
   AuthenticationErrors. Documented in
   `docs/architecture/agent_llm_contract.md`.

2. **Single shared helper.** `agents/shared/shared/llm/mode.py` exposes
   `resolve_audit_mode()` and `is_skills_only()`. All 10 agents call
   through this helper rather than each agent reading
   `os.environ["VULTURE_USE_LLM"]` directly. Single source of truth, easy
   to audit, easy to override in tests.

3. **Make prove honor the contract.** The prove agent's existing
   strategy modules (`prove_agent/strategies/{chaos,owasp,cwe,soc2,
   ssdf,base,shared,rule_analyzer}.py`) become the skills-only
   verification path. Findings the strategies can verify get verified;
   the rest are reported as `inconclusive` with `reason: "no skills-mode
   rule for this category"`. Audit completes successfully; operator gets
   useful (if reduced) output.

4. **Make discover honor the contract.** Plugin-based discovery
   (Playwright + source-file URL extraction) is the skills path; LLM
   endpoint suggestion is the optional `+LLM` enhancement. Skills-only
   discover already produces a usable site map.

5. **Verify the scan-phase 8 are actually compliant.** They delegate to
   `run_combined_audit()`, which is correctly gated — but no test
   currently asserts that **no LLM HTTP call is made** when
   `VULTURE_USE_LLM=false`. Phase 7 adds that assertion via a CI test
   that mocks the LLM endpoint and fails on any unexpected request.

6. **Per-finding `analysis_mode` field.** Every finding declares the
   mode under which it was produced: `"skills_only"`, `"skills_plus_llm"`,
   `"rules_verified"` (prove), or `"plugins_only"` (discover). UI
   surfaces this for transparency.

7. **Reuse feature 0039's degraded-mode banner.** When operator sets
   `VULTURE_USE_LLM=true` but the LLM is unreachable, agents emit the
   canonical `LLMHealthStatus.message()` banner once at audit start. No
   per-call AuthenticationError spam.

## Non-goals

- **Adding new skill rules.** The skill content is whatever each agent
  ships today. We're wiring the dual-mode contract, not expanding
  detection coverage.
- **LLM-required mode upgrade.** `VULTURE_REQUIRE_LLM=true` from feature
  0039 stays as-is — operators who genuinely need LLM (e.g. for prove's
  rule-uncovered findings) can set it and get a hard failure on missing
  config rather than a silent skills-only run.
- **Per-finding LLM choice via CLI flag.** Some operators will want
  `--llm-mode skills|llm|auto` per audit. Out of scope for v1.0; if
  demanded later, a flag plumbs the same env-var contract to per-audit
  config.
- **Replacing prove's existing strategies.** They stay where they are.
  We add a wrapper that runs them in skills mode and falls back to LLM
  in `+LLM` mode.
- **Touching the catalog_detector / secret_scan / etc. CWE skills.**
  Those are skill-only detectors; LLM phase is orchestrated outside.
  No work needed in 0043.

## Design

### The contract

```
docs/architecture/agent_llm_contract.md
```

(New file. ~200 lines.) Spells out:

1. **Mandatory env-var honoring.** Every agent's top-level run function
   MUST call `shared.llm.mode.resolve_audit_mode()` as its first
   meaningful step. The result is one of:
   - `"skills_only"` — operator opted out (`VULTURE_USE_LLM != "true"`)
   - `"skills_plus_llm"` — operator opted in AND LLM is reachable
   - `"degraded"` — operator opted in but LLM is unreachable
   - `"required_failed"` — operator set `VULTURE_REQUIRE_LLM=true` and
     LLM is unreachable (the agent must abort with a clear error)
2. **No silent fallbacks.** When mode flips to `degraded`, the agent
   MUST emit a single `degraded_mode` SSE event carrying the canonical
   `LLMHealthStatus.message()` text. No further LLM-calls-with-cooldown
   loops.
3. **No keyless LLM calls.** Agents MUST NOT invoke any LLM client
   (litellm, OpenAI, Anthropic, Gemini, …) when in `skills_only` or
   `degraded` mode. Static check via Phase 7's CI test asserts this.
4. **Per-finding `analysis_mode`.** Every finding object MUST carry an
   `analysis_mode` string identifying which mode produced it. Schema:
   - `"skills_only"` (scan agents in skills mode)
   - `"skills_plus_llm"` (scan agents in LLM mode)
   - `"rules_verified"` (prove agent, rule-based verification succeeded)
   - `"llm_verified"` (prove agent, LLM-assisted verification)
   - `"plugins_only"` (discover agent, no LLM endpoint suggestion)
   - `"plugins_plus_llm"` (discover agent, LLM-augmented)
5. **Inconclusive results are first-class.** Prove findings the rules
   can't verify in skills mode are emitted as
   `status: "inconclusive", reason: "no skills-mode rule for category=<X>"`,
   not silently dropped, not failed.

### `shared/llm/mode.py`

```python
"""Skills/LLM dual-mode resolution for agents.

Single source of truth for what mode an audit should run in. Reads
``VULTURE_USE_LLM`` and ``VULTURE_REQUIRE_LLM`` (feature 0039), probes
LLM health (feature 0039), and returns a mode tag every agent branches
on.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import NamedTuple

from shared.llm.health import LLMHealthStatus, check_llm_health


class AuditMode(str, Enum):
    SKILLS_ONLY = "skills_only"
    SKILLS_PLUS_LLM = "skills_plus_llm"
    DEGRADED = "degraded"
    REQUIRED_FAILED = "required_failed"


class ModeDecision(NamedTuple):
    mode: AuditMode
    health: LLMHealthStatus | None
    message: str  # canonical banner text; empty for skills_only


def is_skills_only() -> bool:
    """Quick synchronous check — reads the env var only.

    Use when an agent needs to decide whether to import LLM machinery
    at all. For full decision (with health probe), use
    ``resolve_audit_mode()``.
    """
    return os.getenv("VULTURE_USE_LLM", "").lower() != "true"


def is_required() -> bool:
    """``VULTURE_REQUIRE_LLM=true`` — operator wants a hard failure when
    LLM is unreachable, instead of a silent skills-only fallback."""
    return os.getenv("VULTURE_REQUIRE_LLM", "").lower() == "true"


async def resolve_audit_mode(timeout: float = 2.0) -> ModeDecision:
    """Resolve the mode for this audit. Single async call; agents call
    this once at the top of their run function and branch on result.
    """
    if is_skills_only():
        return ModeDecision(AuditMode.SKILLS_ONLY, None, "")

    health = await check_llm_health(timeout=timeout)
    if health.reachable:
        return ModeDecision(AuditMode.SKILLS_PLUS_LLM, health, "")

    # Operator wanted LLM, LLM unreachable.
    if is_required():
        return ModeDecision(
            AuditMode.REQUIRED_FAILED,
            health,
            f"VULTURE_REQUIRE_LLM=true but {health.message()}",
        )

    return ModeDecision(AuditMode.DEGRADED, health, health.message())
```

### Prove agent rewrite (per-finding mode branching)

Current `prove_agent/agent.py:80-91` requires LLM unconditionally. New
shape:

```python
async def run_prove(...):
    decision = await resolve_audit_mode()

    if decision.mode == AuditMode.REQUIRED_FAILED:
        yield emitter.text_message(decision.message)
        yield emitter.run_finished("failed")
        return

    if decision.mode == AuditMode.DEGRADED:
        # Operator opted into LLM but it's unreachable — banner once,
        # then continue in skills-only mode (no per-call cooldowns).
        yield emitter.degraded_mode(decision.message)

    # Always do rule-based verification first.
    rule_results = await run_rule_based_verification(findings, capabilities)

    # Emit each verifiable finding's result.
    for r in rule_results:
        r["analysis_mode"] = "rules_verified"
        yield emitter.prove_result(r)
        yielded.add(r["finding_id"])

    if decision.mode in (AuditMode.SKILLS_ONLY, AuditMode.DEGRADED):
        # Findings the rules can't verify → inconclusive, NOT failed.
        for f in findings:
            if f["id"] in yielded:
                continue
            yield emitter.prove_result({
                "finding_id": f["id"],
                "status": "inconclusive",
                "reason": (
                    f"no skills-mode rule for category={f.get('category')}"
                    " — set VULTURE_USE_LLM=true (and OPENAI_API_KEY or"
                    " equivalent) for LLM-assisted verification"
                ),
                "analysis_mode": "rules_only",
            })
        yield emitter.run_finished("completed")
        return

    # SKILLS_PLUS_LLM: rule-uncovered findings → LLM-assisted prove.
    for f in findings:
        if f["id"] in yielded:
            continue
        llm_result = await prove_with_llm(f, capabilities)
        llm_result["analysis_mode"] = "llm_verified"
        yield emitter.prove_result(llm_result)

    yield emitter.run_finished("completed")
```

`run_rule_based_verification` is a thin wrapper around the existing
`prove_agent/strategies/` modules. Each strategy module already exposes
`verify(finding, target) -> ProveResult | None` — when None, the
strategy doesn't apply and the next strategy is tried. If no strategy
matches, the finding is uncovered.

### Discover agent gating

Current `discover_agent/agent.py` mixes plugin-based discovery
(Playwright crawl, source URL extraction) and LLM-driven endpoint
suggestion. Identify the LLM-call sites and gate them:

```python
async def run_discover(...):
    decision = await resolve_audit_mode()

    if decision.mode == AuditMode.REQUIRED_FAILED:
        yield emitter.text_message(decision.message)
        yield emitter.run_finished("failed")
        return

    if decision.mode == AuditMode.DEGRADED:
        yield emitter.degraded_mode(decision.message)

    # Plugin-based discovery (always runs).
    site_map = await plugins.discover(target_url, ...)

    # LLM endpoint suggestion (gated).
    if decision.mode == AuditMode.SKILLS_PLUS_LLM:
        suggested = await llm_suggest_endpoints(site_map, ...)
        site_map.merge(suggested)

    yield emitter.discover_result(site_map)
    yield emitter.run_finished("completed")
```

`plugins.discover()` already exists. `llm_suggest_endpoints()` is
whatever the current `agent.py` does in its LLM phase.

### Scan agents (verify, no code changes expected)

```bash
# Smoke check: each scan agent produces findings in skills mode without
# any LLM HTTP call. The Phase 7 CI test does this systematically.
VULTURE_USE_LLM=false python -c "
from chaos_agent.agent import run_chaos
async for ev in run_chaos(...):
    ...
"
```

If a scan agent fails this check, the fix is local: trace any direct
LLM call outside `run_combined_audit()` and gate it on
`is_skills_only()`.

### `degraded_mode` SSE event

New event type. Current SSE event taxonomy (per `agent_protocol.md`):
`agent_start`, `thinking`, `finding`, `progress`, `dedup_stats`,
`token_savings`, `result`, `agent_end`. Add `degraded_mode`:

```json
{
  "type": "degraded_mode",
  "message": "LLM unavailable: openai (gpt-4o) at https://api.openai.com — connection refused. Audit will run skills-only.",
  "audit_mode": "degraded"
}
```

Frontend banner already renders this per feature 0039. Backend's
`agui/translator.go` adds a passthrough for the new event type.

### Per-finding `analysis_mode` schema

Add a column to the `findings` table:

```sql
-- 015_finding_analysis_mode.sql
ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_mode TEXT NOT NULL DEFAULT 'skills_plus_llm';
```

Default value `"skills_plus_llm"` for backwards compat — existing rows
were produced under the old (always-LLM) regime.

`prove_results` similarly:

```sql
ALTER TABLE prove_results ADD COLUMN IF NOT EXISTS analysis_mode TEXT NOT NULL DEFAULT 'llm_verified';
```

Go side: extend `model.Finding` and `model.ProveResult` structs.
Repository INSERTs/SELECTs include the new column. Frontend types
update.

### Backwards compatibility

- Existing audits in DB don't have `analysis_mode` → default value
  applied via the migration. UI shows "legacy" tag for those.
- Operators upgrading to 0043 with `VULTURE_USE_LLM=true` set: no
  behavior change. Audits still LLM-driven exactly as before.
- Operators upgrading with `VULTURE_USE_LLM` unset (defaulting to
  false in `dev skills` mode): prove + discover now produce
  inconclusive-for-rules-uncovered output instead of cooldown
  loops. Net win.

### Testing strategy

| Test | Layer | What it asserts |
|---|---|---|
| `test_resolve_audit_mode_skills_only` | unit | `VULTURE_USE_LLM=""` → `SKILLS_ONLY`, no health probe attempted |
| `test_resolve_audit_mode_with_llm` | unit | `VULTURE_USE_LLM=true` + LLM reachable → `SKILLS_PLUS_LLM` |
| `test_resolve_audit_mode_degraded` | unit | `VULTURE_USE_LLM=true` + LLM unreachable + REQUIRE unset → `DEGRADED` |
| `test_resolve_audit_mode_required_failed` | unit | `VULTURE_USE_LLM=true` + REQUIRE=true + LLM unreachable → `REQUIRED_FAILED` |
| `test_prove_skills_only_emits_inconclusive` | unit | Run `run_prove` in skills mode; rule-uncovered findings get `inconclusive` status, not failed |
| `test_prove_skills_only_makes_no_llm_calls` | integration | Patch `litellm.acompletion` to fail the test on any call; assert no calls happen in skills mode |
| `test_discover_skills_only_uses_plugins` | unit | Discover in skills mode produces a site map without invoking LLM endpoint suggestion |
| `test_all_scan_agents_skills_only` | integration | Each of the 8 scan agents runs to completion in skills mode against a tiny corpus, no LLM HTTP call observed |
| `test_no_keyless_authenticationerror_in_logs` | CI workflow | Run the dev-skills smoke; grep logs for `AuthenticationError`; fail if any match |
| `test_degraded_mode_event_emitted_once` | unit | When `VULTURE_USE_LLM=true` but LLM unreachable, exactly one `degraded_mode` SSE event is emitted at start; no per-call cooldown spam |
| `test_legacy_findings_default_analysis_mode` | integration | Existing `findings` rows load with `analysis_mode = "skills_plus_llm"` after migration |

### Performance

- `is_skills_only()` is one `os.getenv()` call — sub-microsecond.
- `resolve_audit_mode()` runs once at audit start (not per-finding).
  Total cost: one LLM health probe (~50-200ms when LLM is reachable;
  effectively cached for 5s by feature 0039's backend aggregator if
  the agent uses it; otherwise direct probe).
- No regression on the `skills_plus_llm` path — same code paths as
  before, just with a single decision-tag prefix.

### Security

- No new attack surface. The contract restricts what agents do; doesn't
  expand any input-handling code.
- `analysis_mode` is server-derived and not influenced by user input;
  not a tampering vector.
- Removing keyless cooldown loops removes a noisy log channel that
  could mask other auth-related errors. Net positive.

### Rollout plan

1. Ship Phase 1 (contract + helper) without changing any agent.
2. Ship Phase 3 (prove rewrite) gated behind a feature flag
   `VULTURE_PROVE_SKILLS_MODE=true`. Default off until Phase 7 CI test
   is green.
3. Same for Phase 4 (discover gating).
4. Once Phase 7 is green for ≥ 1 week, flip the default flag to on.

## Phases

### Phase 1 — Contract definition + shared helper

- [ ] 1.1.t1 — Write `docs/architecture/agent_llm_contract.md` (the
      formal contract spec). ~200 lines.
- [ ] 1.1.t2 — Implement `agents/shared/shared/llm/mode.py` with the
      `resolve_audit_mode()` API.
- [ ] 1.1.t3 — Unit tests for `mode.py`: 5 tests covering the matrix
      `(USE_LLM={set, unset}) × (REQUIRE_LLM={set, unset}) × (LLM
      reachable={yes, no})`.

### Phase 2 — Audit scan-agent compliance

- [ ] 2.1.t1 — Smoke test each of the 8 scan agents in skills mode.
      Confirm zero LLM HTTP calls (mock litellm at module-load time;
      fail on any call).
- [ ] 2.1.t2 — If any scan agent fails the smoke, identify the
      ungated LLM call site and fix locally.
- [ ] 2.1.t3 — Document the audit result in
      `0043_implementation_status.md` decision log.

### Phase 3 — Prove agent rewrite (skills-mode path)

- [ ] 3.1.t1 — Identify all LLM call sites in `prove_agent/`
      (`grep -rn litellm`, `grep -rn openai`, `grep -rn anthropic`,
      `grep -rn ChatCompletion`).
- [ ] 3.1.t2 — Build `run_rule_based_verification()` wrapping the
      existing `strategies/` modules. Each strategy already exposes
      a per-finding verify; new wrapper iterates findings × strategies
      and returns successes (rule_id, evidence, status).
- [ ] 3.1.t3 — Refactor `agent.py::run_prove` to branch on
      `resolve_audit_mode()`:
      - `REQUIRED_FAILED`: error + early exit
      - `DEGRADED`: banner + skills-only path
      - `SKILLS_ONLY`: skills-only path
      - `SKILLS_PLUS_LLM`: rules first, then LLM for uncovered
- [ ] 3.1.t4 — Inconclusive findings get explicit `status` +
      `reason`. Audit completes successfully; doesn't fail.
- [ ] 3.1.t5 — Tests:
      - `test_prove_skills_only_no_llm`
      - `test_prove_uncovered_finding_marked_inconclusive`
      - `test_prove_required_failed_aborts`
      - `test_prove_degraded_emits_banner_once`

### Phase 4 — Discover agent gating

- [ ] 4.1.t1 — Identify LLM call sites in `discover_agent/`.
- [ ] 4.1.t2 — Refactor `agent.py::run_discover` to use
      `resolve_audit_mode()` and gate LLM endpoint suggestion.
- [ ] 4.1.t3 — Tests: `test_discover_skills_only_plugin_path`,
      `test_discover_with_llm_includes_suggestions`.

### Phase 5 — `degraded_mode` SSE event + per-finding `analysis_mode`

- [ ] 5.1.t1 — Add `degraded_mode` event type to
      `agents/shared/shared/transport/event_emitter.py`.
- [ ] 5.1.t2 — Update `backend/internal/agui/translator.go` to
      pass the new event through to the SSE stream (already mostly
      generic — confirm it works).
- [ ] 5.1.t3 — Add `analysis_mode` field to finding-emit calls in
      every agent.
- [ ] 5.1.t4 — DB migration `015_finding_analysis_mode.sql`:
      `ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_mode
      TEXT NOT NULL DEFAULT 'skills_plus_llm'`. Same for
      `prove_results`.
- [ ] 5.1.t5 — Go `model.Finding` + repo INSERTs/SELECTs include
      `analysis_mode`.
- [ ] 5.1.t6 — Frontend `Finding` type adds `analysis_mode?: string`;
      audit-results UI surfaces it as a small label.

### Phase 6 — CI test for skills-mode purity

- [ ] 6.1.t1 — `.github/workflows/skills-mode-purity.yml`: spin up the
      Vulture stack with `VULTURE_USE_LLM=false`, no API key set,
      mock the LLM endpoint via a tiny HTTP server that fails on any
      request. Run a tiny scan + a tiny prove + a tiny discover. CI
      fails if the mock LLM endpoint receives any request.
- [ ] 6.1.t2 — Same job greps the agent logs for
      `AuthenticationError`; any match fails the job.
- [ ] 6.1.t3 — Same job greps for `model_cooldown_start` (the
      cooldown spam pattern); any match fails the job.

### Phase 7 — Documentation + per-agent CLAUDE.md updates

- [ ] 7.1.t1 — Update each agent's `CLAUDE.md` with a "LLM mode"
      section pointing at the contract.
- [ ] 7.1.t2 — Update `docs/architecture/agent_protocol.md` with the
      `degraded_mode` event spec and `analysis_mode` field.
- [ ] 7.1.t3 — Update `docs/guides/cli_usage.md` documenting the
      `dev skills` mode's behavior with prove + discover (now
      produces inconclusive instead of cooldown loops).

### Phase 8 — Default-on rollout

- [ ] 8.1.t1 — After Phase 6 CI is green for ≥ 1 week, remove the
      `VULTURE_PROVE_SKILLS_MODE` feature flag. Skills-mode prove
      becomes the default behavior.
- [ ] 8.1.t2 — Same for discover.
- [ ] 8.1.t3 — Update implementation status with the cutover date.

## Tests

(Detailed list in §Testing strategy above. Total: ~25 tests across
unit, integration, and CI workflow layers.)

## Risks

| Risk | Mitigation |
|---|---|
| Prove agent's value drops sharply without LLM | Honest communication: skills-mode prove verifies what the rules can; rule-uncovered findings are clearly marked `inconclusive` with a hint to enable LLM. Operators understand they're trading thoroughness for cost / no-API-key. |
| Discover endpoint coverage drops | Same mitigation — operator sees "skills-only" tag on the discover result, knows there might be uncovered endpoints. |
| Strategy modules in `prove_agent/strategies/` may have bit-rotted | Phase 3 starts by running each strategy against a known-good corpus to catch any drift before wiring them as the skills path. |
| Migration on production DB churns | Migration is purely additive (`ADD COLUMN IF NOT EXISTS`). Default value covers historical rows. No backfill needed. |
| Frontend `analysis_mode` UI clutter | Show as a small label / tooltip, not a prominent column. Operators can ignore it; auditors who care about provenance can read it. |
| The `degraded_mode` SSE event might not pass through the existing translator cleanly | Phase 5.1.t2 includes a verification step. If it doesn't, add an explicit case to `agui/translator.go`. |
| Phase 6 CI test may be flaky on first ship | Feature-flag the skills-mode behavior (Phase 8 cutover) until CI is reliably green. |
| Operators set `VULTURE_USE_LLM=false` AND expect prove to verify (without realizing) | Documentation: CLI's prove subcommand prints a one-line note when running in skills mode: `Skills-only verification: rule-covered findings will be verified; others reported as inconclusive`. |

## Out-of-scope follow-ups

- **Per-CLI-flag mode override** (`vulture scan --llm-mode skills|llm|auto`) —
  defer until operator demand exists.
- **Tiered LLM use** (some findings via cheap model, others via expensive) —
  separate feature.
- **LLM-only prove fallback** when rules SAY they cover but actually
  produce a low-confidence verdict — defer.
- **Skills coverage reports** (per-category "% of findings rule-verifiable")
  — useful but not load-bearing for the contract.
- **OpenAI Agents SDK loop_guard interaction** — the SDK's tool-call
  cooldown might still misbehave if it sees rare LLM unavailability.
  Track separately if it surfaces.

## Open questions

- **Should `analysis_mode` distinguish `degraded` from `skills_only`?**
  Lean yes — operators may want to filter by "audit ran skills-only
  because operator chose to" vs "audit ran skills-only because LLM
  was down." Use `"degraded"` for the latter.
- **Should the `degraded_mode` event include the `LLMHealthStatus`
  full dict, or just the message string?** Lean message only — the
  full dict is available via the backend `/api/llm/health` endpoint
  for clients that want to drill in.
- **Should prove's `inconclusive` findings count as "completed" or
  "verified=false"?** Lean separate state — `inconclusive` is a
  distinct outcome from `not exploitable` (verified=false). UI shows
  three icons: ✓ (verified), ✗ (not exploitable), ? (inconclusive).
- **Should the migration backfill `analysis_mode` for legacy rows
  based on the audit's `created_at` and the LLM env config at that
  time?** No — too brittle. Default to `"skills_plus_llm"` for
  legacy; ship the column as authoritative going forward.
