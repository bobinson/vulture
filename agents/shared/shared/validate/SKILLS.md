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
