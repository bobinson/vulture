# 0046 — Validate L5: LLM judge (language-aware FP filter)

**Author**: tbd
**Status**: PLANNED (awaiting review)
**Created**: 2026-05-23
**Depends on**: feature 0045 (validation phase L1–L4 shipped),
              feature 0043 (universal skills+LLM contract),
              feature 0039 (unified LLM health)
**Extends**: 0045 §G ("L5 — `llm_judge.py` (opt-in)")

## Table of contents

1. [Goal](#goal)
2. [Why now](#why-now)
3. [Non-goals](#non-goals)
4. [Invariants inherited from 0045](#invariants-inherited-from-0045)
5. [Architecture](#architecture)
6. [Component-by-component design](#component-by-component-design)
   - [A. Package layout](#a-package-layout)
   - [B. Language detection](#b-language-detection)
   - [C. Selection — which findings reach the judge](#c-selection--which-findings-reach-the-judge)
   - [D. Prompt design](#d-prompt-design)
   - [E. Batch I/O contract](#e-batch-io-contract)
   - [F. Response schema + validation](#f-response-schema--validation)
   - [G. Vote contribution](#g-vote-contribution)
   - [H. Caching](#h-caching)
   - [I. Cost + latency control](#i-cost--latency-control)
   - [J. Failure isolation (RC3 conformance)](#j-failure-isolation-rc3-conformance)
   - [K. Compliance-mode interaction (V8)](#k-compliance-mode-interaction-v8)
   - [L. Configuration surface](#l-configuration-surface)
7. [Files touched](#files-touched)
8. [Build sequence](#build-sequence)
9. [Acceptance criteria](#acceptance-criteria)
10. [Security hardening](#security-hardening)
11. [Reliability and chaos](#reliability-and-chaos)
12. [Risks and mitigations](#risks-and-mitigations)
13. [Phasing](#phasing)
14. [Edge cases](#edge-cases)
15. [Out of scope](#out-of-scope)
16. [Open questions for review](#open-questions-for-review)

---

## Goal

Implement layer **L5 (LLM judge)** of the validation phase as specified
in feature 0045 §G. L5 reads the code surrounding a finding, plus the
finding's own metadata, and emits a per-finding **exploitability
probability**. That probability becomes a weighted check in the same
voter as L1–L4, so L5 cannot single-handedly drop or promote a finding
— it joins the ensemble.

The deliverable is **language-aware false-positive suppression at
validate time**: a Java `PreparedStatement` line that the CWE skill
flagged as SQLi should land in `likely_fp` after L5 agrees with at
least one other demoting layer (a test/vendor path, a `// gosec:ignore`
marker, or a labelled neighbour from L4).

## Why now

The 0045 self-scan demonstrated L1–L4 work but with two known gaps:

1. **L1's `SANITIZER_MAP` is hand-curated and Python/JS-skewed.** Java,
   Go's `html/template`, Rust, C# — none of the language-idiomatic safe
   APIs appear in the map, so true sanitizers in those languages don't
   demote findings. The fix isn't more regex; the fix is letting the
   model read the code.

2. **The Tier-2 LLM phase only covers files that fit the context
   window.** Large codebases push most files out of the LLM phase, so
   their findings reach validate having had **zero** LLM judgment
   applied. L5 closes that gap with a single, narrow, batched call per
   suspicious finding — bounded cost, no per-file scan.

The current self-scan shows the impact ceiling: of 1102 findings,
**955 (87%)** classify as `suspicious`. L4 wakes up only once labels
are written. The expanded L1 helped the high_confidence bucket (26 →
142). L5 is the only remaining layer with enough signal to move the
suspicious bucket meaningfully.

## Non-goals

- **L5 is not authoritative.** Per 0045 V7+H3, only `suppression`
  bypasses the ≥2-demoting-checks floor. L5 contributes one vote.
- **L5 is not a static analyser replacement.** It does not chase
  data flow, dereference imports, or resolve callees. It is a
  language-aware exploitability heuristic over a localised window.
- **L5 does not write to the database.** Memory storage / edge
  linking are existing pipelines and remain untouched.
- **L5 does not change the LLM phase (Tier-2).** That phase emits
  findings; L5 judges findings. They can coexist or stand alone.
- **No fine-tuned model.** L5 uses the audit's existing LLM
  (gpt-4o / claude-sonnet / qwen3:1.7b / etc.) via
  `shared.llm.provider`.

## Invariants inherited from 0045

The voter contract (V1–V10), the demote-never-drop rule (V6), and the
layer-isolation rule (RC3) all apply unchanged. Specifically:

- **V6**: L5 never deletes; it only votes. A `verdict=0.0` (definitely
  safe) finding still appears in the output, just at `likely_fp`.
- **V7 + H3**: L5's weight is in `[-0.75, +0.75]`; it cannot solo-demote.
- **RC3**: L5 is wrapped in a try/except. Any failure (timeout, parse
  error, model outage, malformed JSON) records a `ValidationCheck` with
  `weight=0.0` and `reason="error: <type>"`, then the audit proceeds.
- **V9**: total validate latency budget is 60s per audit; L5's share
  is capped at 45s.

## Architecture

L5 runs **inside the audit runner**, after L1+L2 emit their per-finding
checks and before the audit-runner hands findings to the SSE stream. It
does **not** require backend involvement — it's a Python module in
`agents/shared/shared/validate/`. The Go backend's later L3/L4 still
runs unchanged; their checks accumulate with L5's.

```
audit_runner (Python, per agent)
  ├─ skills phase (existing)
  ├─ Tier-2 LLM phase (existing, optional)
  └─ validate()
       ├─ L1 context_heuristics    ◄── runs per finding (deterministic)
       ├─ L2 rollup                 ◄── runs per category (deterministic)
       ├─ L5 llm_judge (NEW)        ◄── runs on selected suspicious set
       │     ↓ batched LLM call, language-aware prompt
       │     ↓ produces ValidationCheck(id="llm_judge", weight=...)
       └─ vote()                    ◄── ensemble of L1+L2+L5
                                          (L3+L4 added by Go backend later)
```

Critical ordering choice: **L5 runs before vote, but after L1+L2.** It
sees L1's per-finding checks (which can include `suppression` — an
authoritative demoter). If `suppression` is already present, L5 is
skipped for that finding — wasting a model call to re-confirm a human
override would be both costly and disrespectful of the V7 priority.

## Component-by-component design

### A. Package layout

```
agents/shared/shared/validate/
  __init__.py                ◄── entry; gains L5 invocation block
  types.py                   ◄── unchanged (ValidationCheck already supports id="llm_judge")
  context_heuristics.py      ◄── unchanged
  rollup.py                  ◄── unchanged
  voter.py                   ◄── unchanged
  llm_judge.py               ◄── NEW
  prompts/
    validate_judge.txt       ◄── NEW system prompt
    validate_judge_user.txt  ◄── NEW user-template with batch slots
```

`llm_judge.py` exposes one function:

```python
def run_l5(
    findings: list[dict],
    l1_results: list[list[ValidationCheck]],
    config: ValidateConfig,
    llm: LLMProvider,        # shared.llm.provider
    audit_id: str = "",
) -> list[list[ValidationCheck]]:
    """For each finding, append zero or one ValidationCheck(id='llm_judge').
    Returns a per-finding list parallel to `findings`."""
```

Return shape is parallel to `l1_results` so the vote loop can simply
extend each finding's check list.

### B. Language detection

A one-shot detector keyed on file extension. No tree-sitter, no
file-content sniffing.

```python
LANGUAGE_BY_EXT = {
    ".py":  "python",   ".pyi": "python",
    ".go":  "go",
    ".ts":  "typescript", ".tsx": "typescript",
    ".js":  "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".java": "java",
    ".kt":  "kotlin", ".kts": "kotlin",
    ".rs":  "rust",
    ".rb":  "ruby",
    ".cs":  "csharp",
    ".php": "php",
    ".c":   "c",   ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh":  "shell", ".bash": "shell",
    ".sql": "sql",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".dockerfile": "dockerfile",
    # Files named "Dockerfile" → handled by basename match
}
```

Unknown extensions return `"unknown"`. The prompt is parameterised on
the language string. We do not enumerate safe APIs in code — the model
already knows the language idiom from its pre-training. We just tell
it what language we're looking at, which prevents the model from
guessing wrong on ambiguous snippets.

### C. Selection — which findings reach the judge

Not every finding gets a model call. Per 0045 §G:

1. **Drop findings already at `likely_fp`** after L1+L2.
   *Why:* L5 only resolves uncertainty; it doesn't double-down on
   confident calls.

2. **Drop findings with a `suppression` check** (operator override).

3. **Sort remainder by** `severity_rank × (1 − current_confidence)`,
   descending.
   - `severity_rank`: critical=4, high=3, medium=2, low=1, info=0.
   - `current_confidence`: derived from a provisional vote over L1+L2
     only.

4. **Cap by config** `validate_llm_top_n` (default **1000** — locked
   2026-05-23 by reviewer to prioritise coverage over cost). The cap
   is per-audit, not per-agent — agents share a budget. On audits
   with > 1000 suspicious findings, the top 1000 by uncertainty-
   weighted severity are judged; the rest land as the L1+L2 vote
   alone, identically to an L5-disabled run.

5. **Batch into groups of `validate_llm_batch_size`** (default **10**).

Findings outside the top-N receive **no L5 check** (not even a
zero-weight stub) — they are treated identically to findings from a
run with L5 disabled. This keeps the system reproducible across runs
with different budgets.

**Coverage at top_n=1000.** The Vulture self-scan produces ~955
suspicious findings (post-L1+L2); essentially all reach L5. stackOpen
(~706 findings) is fully covered. Only very large enterprise
codebases (5k+ findings) approach the cap; selection ensures the most
impactful uncertain findings still get judged first.

### D. Prompt design

Two prompts, both UTF-8 text files (so they're version-controlled and
diffable without code changes). System prompt is short and
deterministic-anchoring:

```
You are a senior security engineer reviewing automated findings. For
each finding you are given the code snippet, surrounding lines, file
language, and the rule it tripped. Your job: estimate the
probability (0.0 to 1.0) that the finding is exploitable AS WRITTEN
in this specific file.

Use language idioms:
- Java: PreparedStatement, ESAPI, Spring validators, @Valid.
- Go: database/sql parameter binding, html/template auto-escape, errcheck conventions.
- Python: parameterised queries, shlex.quote, defusedxml, secrets module.
- JS/TS: parameterised SQL, DOMPurify, template literals with escaping.
- Rust: type-safety (slice bounds), serde_json::from_str, sqlx::query!.
- C/C++: bounds-checked APIs (strncpy_s, snprintf), RAII.

Demote (verdict ≈ 0.1–0.3) when the language's standard safe pattern
is clearly in use. Promote (verdict ≈ 0.7–0.9) when raw concatenation
/ untrusted input clearly reaches a sink. Use 0.5 when genuinely
ambiguous.

Reply with strict JSON only:
{"verdicts":[{"id":"<finding_id>","exploitable":<float>,"reasoning":"<≤60 words>"}]}

No prose outside the JSON. No code blocks. No trailing commas.
```

User-template per batch:

```
Audit ID: {audit_id}
Findings to review ({n} in this batch):

[1] id={f.id}  rule={f.check_id}  severity={f.severity}
    file={f.file_path}  lines={f.line_start}-{f.line_end}
    language={detected_language}
    description: {f.description}
    code:
{code_window}

[2] id={f.id}  ...
```

`code_window` is 10 lines before + the finding line(s) + 10 lines
after, capped at 60 lines total. Lines are 1-indexed and prefixed with
`L<num>: ` so the model can refer to specific lines in its reasoning.

### E. Batch I/O contract

One LLM call per batch, with explicit JSON-mode request (where the
provider supports it: `response_format={"type":"json_object"}` for
OpenAI-compatible, Anthropic tool-use otherwise).

Token budgets per batch (default `batch_size=10`):

| Component | Tokens (approx) |
|---|---|
| System prompt | 350 |
| User template overhead | 200 |
| 10 × (finding metadata) | 10 × 80 = 800 |
| 10 × (code window 60 lines × ~12 tok/line) | 10 × 720 = 7,200 |
| **Input subtotal** | **~8,550** |
| Output (10 verdicts × 100 tok) | 1,000 |
| **Total per batch** | **~9,550** |

For `top_n=100`, batch_size=10 → 10 batches → ~95k tokens/audit.
At gpt-4o-mini ($0.15/1M input + $0.60/1M output), that's roughly
**$0.015 per audit**. At local LM Studio or Ollama, free except for
GPU time.

### F. Response schema + validation

The judge response is parsed with a strict JSON loader. Validation:

1. Top-level must be `{"verdicts": [...]}`. Otherwise the entire batch
   is a parse error → **one retry** is attempted with an "produce
   strict JSON only" follow-up. On second failure, all findings in
   that batch get `weight=0` with `reason="error: malformed response"`.
2. Each verdict must have `id: str`, `exploitable: float in [0,1]`,
   `reasoning: str`. Missing fields → that single finding's check
   becomes `weight=0`.
3. `id` must match a finding in the batch. Stray ids are ignored.
4. Findings present in the batch but missing from the response get a
   `ValidationCheck(id="llm_judge", weight=0.0, reason="no verdict")`.

**Structured output preferences (provider-aware).** L5 requests
schema-constrained output when the provider supports it, falling back
to JSON-mode then plain text in that order:

| Provider | Mechanism | Used when |
|---|---|---|
| OpenAI-compatible (gpt-4o, gpt-oss, LM Studio recent) | `response_format={"type":"json_schema","json_schema":<schema>}` | First choice |
| OpenAI-compatible older | `response_format={"type":"json_object"}` | Schema rejected |
| Anthropic Claude | tool-use with declared output tool | Native |
| Anything else (Ollama, smaller LM Studio models) | Prompt instruction "respond with strict JSON" + post-parse | Fallback |

The retry loop (point 1 above) only applies after the provider's
native structured-output path failed — i.e. a model that ignored the
schema constraint anyway.

The check shape on success:

```python
ValidationCheck(
    id="llm_judge",
    result="real_bug" if v["exploitable"] >= 0.5 else "demoted",
    weight=(v["exploitable"] - 0.5) * 1.5,  # → [-0.75, +0.75]
    reason=v["reasoning"][:200],
    extras={
        "model": llm.model_name,
        "exploitable": v["exploitable"],
        "batch_id": batch_idx,
        "language": detected_language,
        "tokens_in": batch_tokens_in,
        "tokens_out": batch_tokens_out,
    },
)
```

### G. Vote contribution

Weight is `(exploitable − 0.5) × 1.5`, clamped to `[-0.75, +0.75]`.
The `× 1.5` widens L5's influence enough that a confident demotion
(`exploitable=0.1`) combined with one other demoting check (e.g.
`path` at −0.20) lands a finding in `likely_fp` per V7. A confident
promotion (`exploitable=0.9`) alone moves confidence from 0.5 → 1.1 →
clamped to 1.0, landing in `high_confidence`.

L5 cannot trigger the V7 `≥2 demoting checks` rule by itself — it's
only one check. This is correct: an LLM that hallucinates a FP
shouldn't be able to single-handedly hide a real finding.

**No authoritative-positive checks (D8 locked).** Reviewer's principle:
"do the best after audits." The system gets smarter over time through
user labels feeding L4 — not through hardcoded authority on L5
verdicts. An `exploitable=0.95` verdict contributes +0.675 weight,
which combined with the natural +0.10 default seed is already enough
to land in `high_confidence` (0.5 + 0.675 + 0.1 ≈ 1.0). The ensemble
suffices for promotion; no bypass needed. This keeps the model
symmetrically un-trusted in both directions, which matches our
hallucination-risk asymmetry analysis (a wrongly-promoted finding
wastes triage; a wrongly-demoted finding hides a bug — both wrong, but
neither catastrophic when V7 holds).

### G2. Streaming verdict emission (D6 locked)

Each completed L5 batch emits **one** SSE event of type
`validation_update` containing the batch's verdicts. The Python audit
runner's `EventEmitter` gains:

```python
def validation_update_event(
    self,
    findings: list[dict[str, Any]],   # batch of updated findings
) -> str:
    return self._format("validation_update", {
        "phase": "l5_judge",
        "updates": [
            {
                "id": f["id"],
                "validation_status": f["validation_status"],
                "validation_confidence": f["validation_confidence"],
                "validation": f["validation"],
            }
            for f in findings
        ],
    })
```

The Go agui translator gains a matching entry:

```go
"validation_update": func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) {
    return translateValidationUpdate(d)
},
```

`translateValidationUpdate` wraps each update into a StateDelta
`{"op":"replace","path":"/findings/<id>/validation_status","value":...}`
(plus the same for `validation_confidence` and `validation`). The
frontend EventSource handler in `useAgentStream.ts` already processes
StateDelta `replace` ops by id, so the UI updates in place.

**Volume control.** At top_n=1000 / batch=10 → 100 SSE events for L5
alone. Each event carries 10 finding updates. Per-event payload
~10 × 500 bytes = 5 KB → ~500 KB total L5 traffic per audit. Comparable
to existing finding-emission traffic, within budget.

**Cache-hit fast path.** When all findings in a batch hit the
`l5_verdict_cache`, the batch emits its `validation_update` event
immediately without an LLM call. This produces a fast pre-burst on
re-audits before any new LLM batches finish.

**Reconnect resilience.** Verdicts persist to the DB the moment they
arrive (within the batch's transaction). On SSE reconnect, the
existing replay path re-emits the latest validation state from
`audit_memories`, so no data is lost.

### H. Caching

L5 calls are cached on `(file_sha256, line_start, line_end,
finding.check_id, llm.model_name)`. Cache lives in
`audit_memories.l5_verdict_cache` (new column, JSONB, indexed by
that composite key as a hash). TTL: cache hit valid for **30 days**
or until the file's sha256 changes.

This gives us:
- **Cross-audit reuse**: re-scan of unchanged code is free.
- **Within-audit dedup**: two agents flagging the same code path
  share a verdict.
- **Easy invalidation**: a file edit changes its sha256.

Migration `019_l5_verdict_cache.sql` adds the column + index. If the
column is missing (older deployment), L5 silently skips caching — the
extra cost is just re-querying, not a failure.

### I. Cost + latency control

| Variable | Default | Purpose |
|---|---|---|
| `VULTURE_USE_VALIDATE_LLM` | `false` | Master switch — off by default |
| `VULTURE_VALIDATE_LLM_TOP_N` | **`1000`** | Max findings sent to L5 per audit |
| `VULTURE_VALIDATE_LLM_BATCH_SIZE` | `10` | Findings per LLM call |
| `VULTURE_VALIDATE_LLM_TIMEOUT_MS` | **`300000`** (5 min) | Total L5 budget per audit |
| `VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS` | `8000` | Per-batch deadline |
| `VULTURE_VALIDATE_LLM_MAX_CONCURRENCY` | **`5`** | Concurrent batch requests |
| `VULTURE_VALIDATE_LLM_MODEL` | (unset → falls back to `VULTURE_LLM_MODEL`) | Override which model L5 uses |

Batches run with `asyncio.gather` (concurrency-bounded by a
`Semaphore`). Late batches return weight=0 stubs.

**Recalibrated cost at top_n=1000.** 100 batches × ~9.5k input tokens
+ 1k output tokens each:

| Model | Input cost | Output cost | Per-audit |
|---|---|---|---|
| gpt-4o-mini | 950k × $0.15/M = $0.14 | 100k × $0.60/M = $0.06 | **~$0.20** |
| gpt-4o | 950k × $2.50/M = $2.38 | 100k × $10/M = $1.00 | **~$3.40** |
| Claude Sonnet | 950k × $3/M = $2.85 | 100k × $15/M = $1.50 | **~$4.35** |
| Local LM Studio / Ollama | $0 | $0 | **$0** (GPU time only) |

**Latency at top_n=1000.** 100 batches / concurrency 5 = 20
wall-clock batches. At 2–8 s/batch (hosted) or 5–30 s/batch (local
quantized), expected wall-clock L5 latency is **40 s – 10 min**.
Streaming verdicts (D6) means the user sees continuous progress even
during the longer runs.

**Power-user note.** Operators running many audits per day should
configure `VULTURE_VALIDATE_LLM_MODEL` to a cheap, fast model (e.g.
`gpt-4o-mini`) while leaving `VULTURE_LLM_MODEL` on a stronger model
for the Tier-2 audit phase.

### J. Failure isolation (RC3 conformance)

Each layer in validate is independently isolated. L5 conforms by:

```python
try:
    l5_results = run_l5(findings, l1_results, cfg, llm, audit_id)
except Exception as exc:
    log.warning("L5 failed; layer=disabled error=%s", type(exc).__name__)
    l5_results = [[] for _ in findings]   # contributes nothing
```

Per-batch failures (timeout, parse error) collapse to per-finding
`weight=0` stubs without aborting the layer. Network outages, model
unavailability, JSON-malformed responses, and timeout-induced empty
responses all degrade gracefully.

### K. Compliance-mode interaction (V8)

When `compliance_mode=true`, V8 promotes any `likely_fp` back to
`suspicious`. L5 verdicts still record their original
`exploitable` score in `extras` — auditors can see the model's call
even though the bucket is forced back. This satisfies the SOC2 reading
that "no finding may be silently suppressed in compliance review."

**With streaming**, V8 must be applied **per verdict emission**, not
at the end of validate. Otherwise the UI would see a momentary
`likely_fp` flash before the final V8 sweep reverts it — confusing in
compliance contexts. The vote-and-emit helper applies V8 inline before
the SSE event is written:

```python
def _emit_streaming_verdict(finding, l1_check_list, l5_check, cfg):
    finding["validation"]["checks"].append(l5_check.to_json())
    all_checks = [ValidationCheck(**c) for c in finding["validation"]["checks"]]
    status, conf = vote(all_checks)
    v = FindingValidation(status=status, confidence=conf, checks=all_checks)
    if cfg.compliance_mode:
        v = apply_compliance_mode(v)        # ◄── BEFORE emit, not after
    finding["validation_status"] = v.status
    finding["validation_confidence"] = v.confidence
    emit_validation_update(finding)
```

### L. Configuration surface

Three layers of configuration, in order of precedence (highest first):

1. **Audit request body** — `config.validate.llm` (bool) +
   `config.validate.llm_top_n` (int). Per-audit override.
2. **Environment** — `VULTURE_USE_VALIDATE_LLM` + the knobs above.
   Per-deployment default.
3. **Static default** — disabled.

The CLI flag `--validate-llm` (boolean) and `--validate-llm-top-n N`
override (1) for one-off runs.

### M. Model auto-selection

L5 picks its model in this order:

1. **`VULTURE_VALIDATE_LLM_MODEL`** (env or audit config) — explicit
   override.
2. **`VULTURE_LLM_MODEL`** — the audit-time LLM. Default per D12
   (reviewer locked 2026-05-23). Simpler operations: one model
   configured, both phases use it.
3. **Auto-detect from provider's `/v1/models`** — if neither env var
   is set, query the configured `OPENAI_BASE_URL` and pick the first
   model that:
   - Does **not** contain `"embed"` in the id (filters out
     `text-embedding-*`).
   - Matches a known instruction-tuned family (`qwen3`, `gpt-oss`,
     `gemma3`, `gpt-4`, `claude`, `mixtral`, `llama-3`) — preferred.
   - Else: first non-embedding model returned.

The auto-detect path is intended for the dev-mode workflow
(`./scripts/vulture.sh dev lmstudio`) where users have multiple
models loaded and don't want to re-export env vars between runs.

### Recommended local-model recipe (for `SKILLS.md`)

Ship a short table users can pick from based on hardware:

| Tier | Model | RAM/VRAM | Notes |
|---|---|---|---|
| **Recommended** | `qwen3:8b-instruct` | 8 GB | JSON-mode reliable; fast |
| Code-heavy audits | `qwen3-coder-next` | 10–14 GB | Better at compiled-language idioms |
| Strong reasoning | `gpt-oss-20b` | 24+ GB | Catches subtle FPs; slower |
| Constrained | `qwen3:1.7b` | 2 GB | Document the caveat: JSON drift, more parse retries |
| Hosted (paid) | `gpt-4o-mini` | n/a | ~$0.20/audit at top_n=1000 |

These are suggestions, not enforcement. Whatever is loaded in the
local provider works — D11 / D12 explicitly delegates model choice to
the user's environment.

## Files touched

| File | Change |
|---|---|
| `agents/shared/shared/validate/llm_judge.py` | NEW |
| `agents/shared/shared/validate/prompts/validate_judge.txt` | NEW |
| `agents/shared/shared/validate/prompts/validate_judge_user.txt` | NEW |
| `agents/shared/shared/validate/__init__.py` | +20 LOC for L5 invocation, env var read, error isolation |
| `agents/shared/shared/validate/types.py` | +1 ValidateConfig field `validate_llm: bool`, +knobs |
| `agents/shared/tests/unit/validate/test_llm_judge.py` | NEW — parse correctness, batch boundaries, error paths |
| `agents/shared/tests/unit/validate/test_language_detect.py` | NEW |
| `backend/internal/repository/migrations/019_l5_verdict_cache.sql` | NEW — adds `l5_verdict_cache` JSONB col + index on `audit_memories` |
| `backend/internal/handler/audit_handler.go` | +5 LOC — pass `validate.llm` from request body to agent config |
| `cli/main.go` | +30 LOC — `--validate-llm` and `--validate-llm-top-n` flags |
| `docs/features/0046_validate_l5_llm_judge/` | NEW — this plan + status + rollback |
| `agents/shared/SKILLS.md` | +2 lines — document L5 as opt-in |

Lines of code (estimate): ~600 net (mostly the prompts and tests).

## Build sequence

1. **Migration 019** + a backend smoke test that the column is
   nullable + readable. (Independent; merge first.)
2. **Language detector** + unit tests (`test_language_detect.py`).
3. **Prompt files** committed alongside an offline prompt-rendering test
   (no LLM) that snapshots the rendered template for 3 representative
   findings (Python SQLi, Java SQLi, Go `errcheck`).
4. **`llm_judge.py` skeleton**: returns empty per-finding lists, integrated
   into `validate/__init__.py` behind `VULTURE_USE_VALIDATE_LLM`. Verify
   that an audit with the flag set but no model behaves identically to
   one with the flag unset (RC3).
5. **Live LLM path**: enable batched calls, parse responses, write
   ValidationChecks. Verify with `gpt-4o-mini` on the Vulture
   self-scan that:
   - Suspicious bucket shrinks by ≥ 15%.
   - No `weight` outside `[-0.75, +0.75]`.
   - Total L5 latency ≤ 45s on a 100-finding cap.
6. **Caching**: read/write `l5_verdict_cache`, verify cache hit on a
   second consecutive scan of the same source skips all LLM calls.
7. **CLI flags + per-audit config**.
8. **Acceptance tests** (next section).

## Acceptance criteria

1. **Off by default.** A baseline `dev lmstudio --pg` run with the flag
   unset produces identical validation output to v0.1 (commit pre-0046).
2. **Toggleable per-audit.** Setting `config.validate.llm=true` in the
   audit POST body enables L5 for that audit only.
3. **Bucket shift at top_n=1000.** On the Vulture self-scan with L5
   enabled, the suspicious bucket count drops by **≥ 25%** vs. the
   L5-disabled baseline. (Measured against the same source commit;
   threshold raised from the original 15% because at top_n=1000 nearly
   all suspicious findings reach L5.)
4. **Weight clamp.** No persisted finding has a `validation.checks`
   entry with `id="llm_judge"` and `weight` outside `[-0.75, +0.75]`.
5. **Authoritative respected.** Findings that already have a
   `suppression` check have no `llm_judge` entry — we did not waste
   the model call.
6. **RC3 isolation.** With `VULTURE_LLM_MODEL` set to a bogus value
   (`openai/nonexistent-model`), the audit still completes; every
   `llm_judge` check records `weight=0` and `reason="error: ..."`.
7. **Cache hit.** Re-running the same audit against an unchanged
   source produces zero new LLM calls for L5 (verified by
   instrumented counter in `extras.tokens_in` summing to 0 across the
   second run's findings).
8. **Compliance V8 honoured.** With `compliance_mode=true`, no finding
   is classified `likely_fp` even if L5 voted `exploitable=0.01`;
   the verdict is still visible in `extras`.
9. **Streaming progress (D6).** During an L5-enabled audit, the SSE
   stream emits at least one `validation_update` event per completed
   batch, before the final `result` event. The frontend's findings
   table updates the affected rows' `validation_status` in place,
   without a full re-render.
10. **No flash in compliance mode.** With `compliance_mode=true` and
    streaming, no `validation_update` event ever carries
    `validation_status: "likely_fp"` — V8 is applied per-emission.
11. **Auto-selected model is non-embedding.** When neither
    `VULTURE_VALIDATE_LLM_MODEL` nor `VULTURE_LLM_MODEL` is set, the
    auto-detect path picks a chat model, never `text-embedding-*`.
12. **Latency budget.** At top_n=1000 + concurrency=5, total L5
    wall-clock latency is ≤ 300 s on `gpt-4o-mini` (hosted) or
    ≤ 600 s on a local 8B-quant model. Above the budget, late batches
    record `weight=0` stubs and the audit still completes.

## Security hardening

- **SH5-L5**: prompt files are read-only; runtime path is validated
  against `agents/shared/shared/validate/prompts/` to prevent prompt
  injection via path traversal.
- **SH6-L5**: model response is parsed with `json.loads()`, never
  `eval()`; max-response-size cap (default 64 KB) prevents OOM from a
  pathological response.
- **SH7-L5**: `reasoning` field is truncated to 200 chars before
  persistence; HTML-escaped at render time on the frontend.
- **SH8-L5**: cache key includes `llm.model_name` to prevent
  cross-model cache poisoning.

## Reliability and chaos

- **RC3-L5**: layer try/except wrapper (already covered above).
- **RC4-L5**: batch-level timeout (8s default); a single hung batch
  cannot block the rest of validate.
- **RC5-L5**: bounded concurrency via Semaphore prevents thundering
  herd against a local LLM.
- **RC8-L5**: large finding sets (`>top_n`) silently drop excess —
  predictable, not error.

## Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Model hallucinates a FP, hides a real bug | Medium | High | Weight clamp at ±0.75; L5 alone can't trigger V7 ≥2-check rule; suppression markers still authoritative |
| Cost runaway on large audits | Medium | Medium | Hard cap `top_n=100`; per-batch token budget; deterministic per-audit ceiling |
| Local LM Studio model is too small to follow JSON contract | High | Low | Parse-failure path degrades gracefully to weight=0; documented model recommendations in `SKILLS.md` |
| Prompt regression breaks cached verdicts | Low | Low | Cache key includes prompt version hash; bumping prompt invalidates cache |
| Latency exceeds 45s on hosted models | Medium | Medium | Per-batch deadline, concurrent batches; late batches contribute weight=0 |

## Phasing

- **Phase 1 (this feature)**: implement L5 behind opt-in flag.
  No defaults change. Self-scan validates bucket shift.
- **Phase 2 (deferred)**: tune `top_n` default upward once cost data
  from real audits is available; consider making `validate_llm=true`
  the default if FP suppression proves reliable.
- **Phase 3 (deferred, separate feature)**: feed L5 verdicts back into
  L4's labelled corpus as weak labels so the memory layer can amplify
  L5's calls in future audits.

## Edge cases

- **Empty code window** (finding line 1, file < 21 lines): include the
  whole file. Truncate at 60 lines max.
- **Binary or generated file** (the file scanner shouldn't have
  produced findings here, but defensively): if `code_snippet` is empty
  or non-UTF-8, skip L5 for that finding.
- **Finding with no `file_path`** (e.g. project-level SSDF findings):
  skip L5; weight=0 stub recorded for traceability.
- **Mixed-language file** (`.html` with embedded `<script>`,
  `.md` with code fences): language detector returns `"html"` /
  `"markdown"`; the prompt language hint is just a hint, the model
  still sees the code.

## Out of scope

- **Multi-pass refinement.** No "judge then re-judge" loop. One verdict
  per finding per audit.
- **Per-rule prompt customisation.** All rules use the same prompt.
  Rule-specific tweaks can move to L1 sanitizers cheaply.
- **Streaming verdicts to the UI.** L5 is batched and emitted at the
  end of validate alongside L1/L2; no incremental SSE during the L5
  phase. (Discuss in review if this should change.)

## Open questions for review

**All five locked by reviewer 2026-05-23.** Decisions captured below;
historical question text preserved for traceability.

1. **`validate_llm_top_n` default — LOCKED at 1000.** Reviewer:
   "make it 1000 to begin with to ensure quality findings." Effect:
   most audits get full coverage of the suspicious bucket; cost is
   ~$0.20/audit on gpt-4o-mini, $0 locally. Recalibrated latency,
   concurrency, and timeout to match (see §I).

2. **Streaming — LOCKED enabled.** Reviewer: "streaming." Effect: new
   SSE event type `validation_update`, one per completed batch. Better
   UX especially at top_n=1000 where total L5 latency may be minutes.
   V8 applied per-emission to avoid `likely_fp` flashes in compliance
   mode.

3. **L5 sees L4's memory verdict — DEFERRED to Phase 2.** Reviewer's
   "do the best after audits" principle: the system gets smarter via
   user feedback feeding L4 in *future* audits, not by introducing
   tight intra-audit coupling between Python validate and Go
   aggregator. Keep L5→L4 ordering for v1.

4. **Authoritative-positive checks — LOCKED to no.** Reviewer:
   "do the best after audits . ultrathink." Deep reasoning: an
   `exploitable=0.95` verdict already contributes +0.675 weight, which
   combined with the natural +0.10 path seed is enough for
   `high_confidence` via ensemble. Adding authoritative-positive
   would let a single hallucinated verdict bump noise into the
   confident bucket — asymmetric risk vs symmetric trust.
   `AUTHORITATIVE_CHECKS` remains `{"suppression"}`.

5. **Local-model recipe — LOCKED to ship with auto-detect fallback.**
   Reviewer: "ship a local self model reco though often use whatever
   is running locally." Effect: `SKILLS.md` gains a recommended
   model table (§M); the runtime auto-detects whatever's loaded in
   the configured LLM provider when no env override is set.

6. **L5 model selection — LOCKED to same as audit LLM.** Reviewer:
   "same." Default `VULTURE_VALIDATE_LLM_MODEL` falls back to
   `VULTURE_LLM_MODEL`. Override path exists for cost-sensitive
   deployments (use cheap model for L5, strong model for the audit's
   Tier-2 phase).

### Additional decisions surfaced during ultrathink

7. **D13: Total budget scales for top_n=1000** — default
   `VULTURE_VALIDATE_LLM_TIMEOUT_MS=300000` (5 min).
8. **D14: One JSON-parse retry per batch.** Reduces local-model FP
   rate (~5% parse-error baseline → ~0.5%).
9. **D15: Structured outputs preferred** — `json_schema` then
   `json_object` then prompt-instruction fallback.
10. **D16: V8 applied per emission** in streaming mode (not at end).
11. **D17: Auto-select non-embedding model** from `/v1/models`.
12. **D18: Concurrency raised to 5** (was 3) for top_n=1000 throughput.
13. **D19: SSE event per batch, not per verdict** — keeps event count
    bounded at top_n/batch_size = 100.
14. **D20: Startup warning if `l5_verdict_cache` column missing** —
    backend log marks caching as disabled instead of failing silently.

## References

- Feature 0045 (`docs/features/0045_validation_phase/`) — parent.
- Feature 0043 — universal LLM contract that L5 reuses.
- Feature 0039 — LLM health check that gates L5 on a working provider.
- 0045 §G "L5 — `llm_judge.py` (opt-in)" — original spec; this plan
  expands it with language detection, caching, V8 interaction, RC3
  conformance, and concrete prompts.
