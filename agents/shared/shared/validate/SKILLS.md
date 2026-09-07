# Validate package — skills

The validate package classifies findings into `high_confidence`,
`suspicious`, and `likely_fp` buckets via a layered ensemble. It is
**not an agent** in the traditional sense — it runs inside every
audit agent's `audit_runner` pipeline between the skill+LLM phases
and the SSE emit.

> **Plugin authors**: feature 0046 (L5 LLM judge) is in-tree, but the
> validate phase accepts plugin extensions per the
> [vulture-plugin/1.0 contract](../../../../docs/spec/plugin-v1/contract.md).
> A validate plugin emits `validation_update` events with new
> `ValidationCheck` entries; the voter combines them with in-tree
> L1–L5.

> **Note:** L1, L2, and L5 are implemented in Python (this package).
> L3 (cross-agent) and L4 (memory_prior) live in the Go backend
> (`backend/internal/handler/stream_handler.go`,
> `backend/internal/service/validation_memory.go`). The full ensemble
> spans both languages — this file only documents the Python side.

## Layers

| Layer | Where it runs | Description |
|---|---|---|
| L1 — context_heuristics | Python (`agents/shared/shared/validate/context_heuristics.py`) | Path classifier + suppression-marker scan + per-CWE sanitizer map |
| L2 — rollup | Python (`rollup.py`) | Groups N findings of the same shape into one parent row |
| L3 — cross_agent | Go (`backend/internal/handler/stream_handler.go`) | Boosts confidence when ≥2 agents flag the same line |
| L4 — memory_prior | Go (`backend/internal/service/validation_memory.go`) | Inherits ±0.40 weight from user-labelled neighbours |
| L5 — llm_judge | Python (`llm_judge.py`) | LLM verdicts on language-specific exploitability |

## L5 — local model recipe (feature 0046)

L5 calls the configured LLM (`VULTURE_VALIDATE_LLM_MODEL` →
`VULTURE_LLM_MODEL` fallback → auto-detected from `/v1/models`) with
the code window + finding metadata + language hint. The response is
strict JSON: `{"verdicts":[{"id":...,"exploitable":0..1,"reasoning":...}]}`.

### Recommended models

| Tier | Model | RAM/VRAM | Notes |
|---|---|---|---|
| **Recommended** | `qwen3:8b-instruct` | 8 GB | JSON-mode reliable; fast (~2–4 s/batch) |
| Code-heavy audits | `qwen3-coder-next` | 10–14 GB | Better at compiled-language idioms |
| Strong reasoning | `gpt-oss-20b` | 24+ GB | Catches subtle FPs; ~5–10 s/batch |
| Strong reasoning (deep) | `qwen3.6-35b-a3b` / `google/gemma-4-31b` | 32–48 GB | ~15–30 s/batch; bump `VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS=60000` |
| Constrained | `qwen3:1.7b` | 2 GB | JSON drift common; the one-retry path absorbs most |
| Hosted (paid) | `gpt-4o-mini` | n/a | ~$0.20/audit at top_n=1000; fastest hosted option |

Auto-detection prefers whatever's loaded in your local provider — these
are suggestions, not enforcement. The runtime filters out embedding
models (`text-embedding-*`) automatically.

### Tuning

| Env var | Default | When to change |
|---|---|---|
| `VULTURE_USE_VALIDATE_LLM` | `false` | Set `true` to enable L5 |
| `VULTURE_VALIDATE_LLM_TOP_N` | `1000` | Lower for faster runs; raise only for very large codebases |
| `VULTURE_VALIDATE_LLM_BATCH_SIZE` | `10` | Lower if your model parses JSON unreliably |
| `VULTURE_VALIDATE_LLM_MAX_CONCURRENCY` | `5` | Drop to 1–2 for small local GPUs |
| `VULTURE_VALIDATE_LLM_TIMEOUT_MS` | `300000` (5 min) | Raise for very large codebases or very slow models |
| `VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS` | `30000` (30 s) | Raise to 60–120 s for ≥20B local models |
| `VULTURE_VALIDATE_LLM_MODEL` | (unset) | Override the L5 model independently of the audit's main LLM |

**The judge's tools are unconditional.** It holds read-only `read_file`,
`search_pattern` and `parse_ast`, confined to the scanned root, wherever a
source root is available — there is no switch. The tool budget is fixed at 4
calls per batch request (enough to read a span and search twice); exhausting it
yields *could not decide* for the whole batch, never a verdict built on the
partial view. Because that budget is per batch, lower
`VULTURE_VALIDATE_LLM_BATCH_SIZE` to 1–3 when you want the judge to actually
use the tools. A provider that rejects the `tools=` parameter is handled by the
fallback in `_judge_batch`, which degrades that batch to plain judging.

### Obligation gate knobs (feature 0072)

| Env var | Default | When to change |
|---|---|---|
| `VULTURE_OBLIGATION_MODE` | `observe` | `enforce` withholds/removes labels per the obligation gate. `observe` records the true state but changes no status (AC22) |
| `VULTURE_L5_OBLIGATIONS` | `true` | **Runtime kill switch.** `false` disables the obligation gate entirely — no label withheld, no finding dismissed on an obligation — *even under `enforce`*, without reverting to `observe` or rebuilding. The rollback plan's one-lever safety valve. (The judge's closure admissibility is separate — see `VULTURE_L5_CLOSURE_GATE`.) |
| `VULTURE_OBLIGATION_STRICT_SCOPE` | (off) | Forces `degradable` classes to behave non-degradably: an obligation whose declared scope has no resolver stays `unknown` rather than discharging at a narrower scope |
| `VULTURE_L5_PROMOTION_CLOSURE` | (tracks mode) | §5.3 condition 1: a lone promoting judge verdict may confirm a finding **alone** only if it asserted its analysis window was sufficient (`window_sufficient` is `True`). Default follows `VULTURE_OBLIGATION_MODE` — on under `enforce`, off under `observe`. `true` requires closure even in `observe` (measurement); `false` restores the pre-fix probability-only promotion (rollback). Unaffected when the judge is corroborated by another promoter |
| `VULTURE_CALIBRATION_FILE` | (unset) | Path to `{"demoted_rules": ["check-id-or-category", …]}`. A listed rule is demoted to candidate-only (P7) under `enforce`, regardless of its class's scope-review state. A broken/unreadable file fails **open** (demotes nothing) and self-heals when fixed |

### L5 selection policy (feature 0072 P6, T6.3)

Which findings reach the judge is a **stated policy**, not an emergent
property of snippet attachment. In order:

1. **Code window required.** A finding whose `code_snippet` is empty or
   whitespace-only is never judged (`_has_code_window`) — the judge is not
   asked to reason about an empty block. Windows are back-filled for every
   provenance tier by `audit_runner._attach_code_snippet`, but a finding
   whose `file_path` cannot be resolved or whose `line_start` is 0 keeps an
   empty window and is therefore excluded. This is how an entire provenance
   tier can silently miss L5 (observed: 0 of 14 LLM-detector findings judged
   in one measured run).
2. **Already-dismissed findings are skipped.** An operator suppression
   marker, or the V7 dismissal rule already satisfied (`confidence < 0.30`
   with ≥ 2 demoting checks), skips the LLM call the voter would ignore.
3. **Priority ranking, then `top_n`.** Survivors are ranked by
   `severity_rank × (1 − provisional_confidence)` — most-uncertain-and-
   severe first — and the top `VULTURE_VALIDATE_LLM_TOP_N` are judged.

Every finding leaving `validate()` carries a `coverage` check naming the
outcome: `judged`, `skipped_no_window`, `skipped_already_likely_fp`,
`skipped_budget_exhausted`, `skipped_not_selected`, `skipped_l5_disabled`,
or `judge_error`. A judge that returned no verdict is `judge_error`, never
`judged`. The check is informational — weight `0.0`, read by no voter
branch — so a missing L5 verdict can never block or grant confirmation.
The run summary aggregates the same data per skip reason and provenance
(`[validate] L5 coverage · …`).

### Judge independence (T6.5)

`VULTURE_VALIDATE_LLM_MODEL` is the knob for an **independent** judge.
When it is unset, L5 falls back to the detector's own
`VULTURE_LLM_MODEL` — i.e. **the default configuration is self-review**:
the model that proposed a finding also scores it, with correlated errors.
Deployments that rely on L5 as a check on the detector should set
`VULTURE_VALIDATE_LLM_MODEL` to a different model family.

### Cost (hosted)

At top_n=1000, batch_size=10 → ~95k tokens/audit:

| Model | Per-audit |
|---|---|
| `gpt-4o-mini` | ~$0.20 |
| `gpt-4o` | ~$3.40 |
| Claude Sonnet | ~$4.35 |
| Local | $0 (GPU time only) |

## Per-audit override

Pass `config.validate.llm=true` in the audit POST body or
`--validate-llm` on the CLI to enable L5 for a single audit:

```bash
vulture scan ~/src/myproject --validate-llm --validate-llm-top-n 200
```

Combine with `compliance_mode=true` to prevent any finding from
landing in `likely_fp` regardless of L5's verdict — the original
exploitability score is still recorded in `validation.checks[].extras`
for auditor review.

## Feature 0076 (LLM evidence quotation) — no new skill (T5.9)

**Stated explicitly so the omission reads as a decision, not an oversight:
feature 0076 adds no agent skill, and therefore requires no change to any
agent's `SKILLS.md`.**

A *skill* is a detector — it proposes findings. 0076 proposes nothing. It
constrains and checks what the LLM tier has already proposed:

| 0076 surface | Kind | Where documented |
|---|---|---|
| `shared/anchor.py`, `shared/tools/line_format.py` | prompt presentation + anchor resolution | code docstrings; `CLAUDE.md` env table |
| the required `evidence_quote` field | contract on the LLM tier's output | plan §5.2/§5.3 |
| the quote/anchor verifier | a **validation check**, not a skill — it joins L1–L5 in the voter's ensemble, weighted by `VULTURE_LLM_QUOTE_VERIFY` | this file's layer table |

Consequently every agent's skill inventory is unchanged by 0076: the same
detectors run, over the same files, emitting the same categories. What
changes is how much of a finding is *verifiable* after the fact.

The corollary for reviewers: an audit of 0076 that looks for a new entry in
`agents/*/…/skills/SKILLS.md` and finds none has found the intended state.
