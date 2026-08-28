"""Shared audit runner with concurrent skill execution and file caching."""

import asyncio
import contextvars
import functools
import json
import logging
import os
import re
import time
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from pydantic import BaseModel, create_model

from shared import anchor
from shared.cancellation import (
    current_audit_deadline,
    current_cancel_token,
    set_audit_deadline,
)
from shared.env import env_flag, env_truthy
from shared.llm.errors import retry_skill
from shared.tools import line_format
from shared.tools.category_enum import normalize_to_enum
from shared.tools.file_scanner import (
    clear_caches,
    is_entry_or_config,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.finding_collapse import collapse_line_stacks
from shared.tools.memory_client import _normalize_title, estimate_tokens, safe_estimate_tokens
from shared.tools.snippet import extract_snippet
from shared.transport.event_emitter import AgUiEventEmitter

logger = logging.getLogger(__name__)


def _safe_int_env(name: str, default: int) -> int:
    """Read an integer from an env var, returning *default* on empty/missing/invalid."""
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        logger.warning("invalid_env_int var=%s value=%r using_default=%d", name, val, default)
        return default


# Max concurrent skill workers. Override via VULTURE_SKILL_WORKERS env var.
# Default caps at 8: skills are I/O-bound (regex on files), so 8 workers
# saturate disk I/O without excessive thread overhead.  For CPU-bound
# workloads or high-core machines, tune via VULTURE_SKILL_WORKERS.
_SKILL_WORKERS = _safe_int_env("VULTURE_SKILL_WORKERS", min(os.cpu_count() or 4, 8))

# Pre-compiled patterns for _parse_llm_findings (avoid per-call re.compile).
# The BARE pattern is no longer part of the default attempt order (feature 0076
# B1): a non-greedy ``}\s*]`` cannot survive a string value that itself contains
# ``}]``, and ``[{ id: 1 }]`` is an everyday TS/JSX literal — so a model quoting
# such a line loses the WHOLE batch. ``_scan_json_arrays`` replaces it;
# ``VULTURE_LLM_JSON_SCAN=false`` puts the regex back.
_LLM_JSON_FENCED_RE = re.compile(r"```json\s*(\[.*?\])\s*```", re.DOTALL)
_LLM_JSON_BARE_RE = re.compile(r"(\[\s*\{.*?\}\s*\])", re.DOTALL)

# The keys that make a decoded array look like a findings payload. `id` is
# deliberately absent: it is the only key of the everyday decoy
# ``[{"id":1},{"id":2},{"id":3}]``, and admitting it would let a three-row TS
# example in model prose outrank the real one-row answer.
_FINDING_KEYS = frozenset({
    "title", "severity", "category", "file_path", "line_start",
    "line_end", "description", "recommendation", "evidence_quote",
})

# TWO fields, TWO switches — they are not the same risk (0076 §5.1, recall-3).
# ``code_snippet`` is a fabricated-evidence risk; ``check_id`` is a DEDUP
# IDENTITY whose naive removal deletes rows (AC26). Collapsing them into one
# constant would make it impossible to reverse a dedup regression without also
# re-trusting model-authored evidence.
_MODEL_FORBIDDEN_SNIPPET = ("code_snippet",)    # VULTURE_LLM_TRUST_MODEL_SNIPPET
_MODEL_FORBIDDEN_CHECK_ID = ("check_id",)       # VULTURE_LLM_TRUST_MODEL_CHECK_ID
_TRUST_MODEL_SNIPPET = "VULTURE_LLM_TRUST_MODEL_SNIPPET"
_TRUST_MODEL_CHECK_ID = "VULTURE_LLM_TRUST_MODEL_CHECK_ID"


class AuditFinding(BaseModel):
    severity: str = "info"
    category: str = "unknown"
    title: str = "Untitled finding"
    description: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    recommendation: str = ""
    check_id: str = ""
    # Feature 0057 P0.1: code window read from the source, used to ground the
    # L5 judge (R4) so it never judges blind. Populated centrally by
    # _attach_code_snippet() just before validation, then egresses into the SSE
    # ``result`` event and the pre-existing DB ``code_snippet`` column (R7). For
    # secret-bearing CWEs (CWE-798/CWE-319 etc.) the secret VALUE is redacted at
    # that same choke point so neither the SSE payload nor the DB row carries it.
    code_snippet: str = ""
    # Feature 0076 §5.2: the model's own evidence — 1-3 source lines copied
    # VERBATIM out of the file it is accusing, which is what makes the claim
    # checkable without a model. PRIVATE: it is stripped at the parse choke point
    # (``_strip_private_fields``) and never reaches SSE, the DB or the L5 prompt.
    evidence_quote: str = ""


class AuditOutput(BaseModel):
    findings: list[AuditFinding]


# The finding fields the MODEL is shown. ``code_snippet`` and ``check_id`` are
# deliberately absent (0076 B3): the first is a source-read artefact produced by
# ``_attach_code_snippet`` — a model-authored string is indistinguishable from a
# real read, displaces the L5 window and scores +3 in the Go winner selection —
# and the second is never persisted by either repository, so a model-invented
# value is pure noise that nonetheless keys the Python dedup identity.
_MODEL_VISIBLE_FIELDS: tuple[str, ...] = (
    "severity", "category", "title", "description",
    "file_path", "line_start", "line_end", "recommendation",
)


@functools.lru_cache(maxsize=2)
def _model_visible_output(with_quote: bool) -> type[BaseModel]:
    """The structured response schema, built from ``AuditFinding``'s own fields.

    ``AuditFinding`` stays WIDE: it is the internal carrier every parse path
    fills. What the model is SHOWN is this narrower projection of it, so there is
    still one authority for each field's type and default. Cached on the single
    switch it depends on — the switch itself is read at call time by the caller.
    """
    names = _MODEL_VISIBLE_FIELDS + (("evidence_quote",) if with_quote else ())
    fields: dict[str, Any] = {
        name: (AuditFinding.model_fields[name].annotation,
               AuditFinding.model_fields[name].default)
        for name in names
    }
    finding = create_model("AuditFinding", **fields)
    return create_model("AuditOutput", findings=(list[finding], ...))


SkillFn = Callable[[str], dict]

USE_LLM = os.environ.get("VULTURE_USE_LLM", "false").lower() == "true"

# Severity weights for score computation (shared across all agents).
_SEVERITY_WEIGHTS = {"critical": 10.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}

# Map LLM abbreviations/variants to canonical severity names.
_SEVERITY_ALIASES: dict[str, str] = {
    "c": "critical", "crit": "critical", "critical": "critical",
    "h": "high", "high": "high",
    "m": "medium", "med": "medium", "medium": "medium",
    "l": "low", "low": "low",
    "i": "info", "info": "info", "informational": "info",
}


def normalize_severity(raw: str) -> str:
    """Normalize severity string from LLM output to canonical lowercase form."""
    return _SEVERITY_ALIASES.get(raw.lower().strip(), "info")


def _emit_token_savings(
    emitter: AgUiEventEmitter,
    context: str,
    findings_total: int = 0,
    findings_skipped: int = 0,
    actual_input_tokens: int = 0,
    actual_output_tokens: int = 0,
    model: str | None = None,
    prior_lines: list[str] | None = None,
) -> str | None:
    """Build a token savings SSE event based on real deduplication metrics.

    Args:
        emitter: Event emitter instance.
        context: Prior context string.
        findings_total: Total findings (new + known).
        findings_skipped: Findings skipped because they matched prior context.
        actual_input_tokens: Real input tokens from LLM API response.
        actual_output_tokens: Real output tokens from LLM API response.
        model: Model key for cost estimation.
        prior_lines: Pre-split context lines. Avoids redundant split when
            the caller has already split the string.

    Returns:
        SSE event string, or None if no context.
    """
    if not context:
        return None
    ctx_tokens = estimate_tokens(context)
    ctx_lines = prior_lines if prior_lines is not None else context.split("\n")
    used = sum(1 for ln in ctx_lines if ln.startswith(" ") and ":" in ln)
    dupes = _extract_dupe_count(ctx_lines)

    # Estimate raw tokens: what we'd have used without memory context
    # Each skipped finding would have been ~65 tokens of LLM output + analysis
    if findings_skipped > 0:
        skipped_output_tokens = findings_skipped * 65
        raw_tokens = ctx_tokens + skipped_output_tokens
    else:
        # No findings were skipped — context was informational only, no savings
        raw_tokens = ctx_tokens

    # Compute cost if actual usage is available
    cost_usd = 0.0
    if actual_input_tokens > 0 or actual_output_tokens > 0:
        from shared.llm.provider import estimate_cost
        cost_usd = estimate_cost(actual_input_tokens, actual_output_tokens, model)

    return emitter.token_savings_event(
        ctx_tokens, raw_tokens, used, dupes,
        actual_input_tokens=actual_input_tokens,
        actual_output_tokens=actual_output_tokens,
        cost_usd=cost_usd,
    )


def _parse_known_titles(
    prior_context: str,
    prior_lines: list[str] | None = None,
) -> set[str]:
    """Extract normalized known issue titles from prior context string.

    Parses lines like ' C:[injection] SQL Injection @db.py' to extract 'sql injection'.

    Args:
        prior_context: Raw prior context string.
        prior_lines: Pre-split lines. Avoids redundant split when
            the caller has already split the string.
    """
    titles: set[str] = set()
    if not prior_context:
        return titles
    for line in (prior_lines if prior_lines is not None else prior_context.split("\n")):
        line = line.strip()
        if not line or line.startswith(("Known", "Skip", "(")):
            continue
        # Format: "C:[category] Title @file" or "C:Title @file"
        if ":" in line:
            after_sev = line.split(":", 1)[1]
            # Remove @file suffix
            if " @" in after_sev:
                after_sev = after_sev.rsplit(" @", 1)[0]
            # Remove [category] prefix if present
            if after_sev.startswith("["):
                bracket_end = after_sev.find("] ")
                if bracket_end >= 0:
                    after_sev = after_sev[bracket_end + 2:]
            titles.add(_normalize_title(after_sev))
    return titles


def _extract_dupe_count(lines: list[str]) -> int:
    """Extract duplicate count from prior context lines."""
    for ln in lines:
        if "duplicates" in ln and "excluded" in ln:
            m = re.search(r"\((\d+)", ln)
            if m:
                return int(m.group(1))
    return 0


def _check_context_budget(prompt_text: str, model: str | None = None) -> tuple[str | None, int]:
    """Check if prompt fits within model's context window.

    Returns ``(warning_or_none, estimated_tokens)`` so callers can reuse
    the token count instead of re-estimating.  The 80% threshold matches
    the truncation target in ``_truncate_prompt_to_budget``.
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window(model)
    estimated_tokens = safe_estimate_tokens(prompt_text)
    budget_pct = estimated_tokens / ctx_tokens if ctx_tokens > 0 else 1.0
    if budget_pct > 0.8:
        logger.warning(
            "context_budget_exceeded estimated=%d ctx_window=%d pct=%.0f%%",
            estimated_tokens, ctx_tokens, budget_pct * 100,
        )
        warning = (
            f"Prompt ({estimated_tokens} est. tokens) exceeds 80% of "
            f"context window ({ctx_tokens} tokens). Truncating to fit."
        )
        return warning, estimated_tokens
    return None, estimated_tokens


def _truncate_prompt_to_budget(
    prompt_text: str,
    model: str | None = None,
    estimated_tokens: int | None = None,
) -> str:
    """Truncate prompt by removing whole low-priority file blocks.

    Instead of slicing at an arbitrary character position (which could
    cut mid-function), this removes file blocks from the end (lowest
    priority) until the prompt fits within 80% of the context window.

    Args:
        prompt_text: The full prompt string.
        model: Optional model key for context window sizing.
        estimated_tokens: Pre-computed token count from ``_check_context_budget``.
            When provided, skips a redundant whole-prompt encode.
    """
    from shared.llm.provider import get_context_window

    ctx_tokens = get_context_window(model)
    target_tokens = int(ctx_tokens * 0.8)

    # Cheap pre-check: if caller already estimated and the prompt fits,
    # we're done before any encoding work.
    if estimated_tokens is not None and estimated_tokens <= target_tokens:
        return prompt_text

    # Split on file boundaries ("--- path ---") so we can remove whole files.
    file_marker = "\n\n--- "
    parts = prompt_text.split(file_marker)
    if len(parts) <= 1:
        # No file blocks — fall back to char truncation. Encode here only
        # if the caller didn't already.
        estimated = estimated_tokens if estimated_tokens is not None else safe_estimate_tokens(prompt_text)
        if estimated <= target_tokens:
            return prompt_text
        ratio = len(prompt_text) / max(estimated, 1)
        target_chars = int(target_tokens * ratio)
        return prompt_text[:target_chars] + "\n\n[... truncated to fit context window ...]"

    # parts[0] is everything before the first file; parts[1:] are file blocks.
    preamble = parts[0]
    file_blocks = [file_marker.lstrip("\n") + p for p in parts[1:]]

    # Per-block token counts — these dominate the encode work, but each
    # block is encoded exactly once (no O(N²) re-encoding inside the loop).
    preamble_tokens = safe_estimate_tokens(preamble)
    block_tokens = [safe_estimate_tokens(b) for b in file_blocks]
    separator_tokens = safe_estimate_tokens("\n\n")
    running_total = preamble_tokens + sum(block_tokens) + separator_tokens * len(block_tokens)

    # Reuse the per-block sum as our total estimate (avoid encoding the
    # whole prompt a second time just to log it). Only meaningful when
    # the caller didn't already provide estimated_tokens.
    if estimated_tokens is None:
        estimated_tokens = running_total

    # If the prompt was within budget after all (caller's pre-estimate
    # was conservative) we can return unchanged.
    if running_total <= target_tokens:
        return prompt_text

    # If preamble alone exceeds budget, truncate it directly.
    if preamble_tokens > target_tokens:
        ratio = len(preamble) / max(preamble_tokens, 1)
        target_chars = int(target_tokens * ratio)
        return preamble[:target_chars] + "\n\n[... truncated to fit context window ...]"

    # Remove file blocks from the end (lowest priority) until budget met.
    while file_blocks and running_total > target_tokens:
        running_total -= block_tokens.pop() + separator_tokens
        removed = file_blocks.pop()
        logger.debug("truncation_removed_file block_len=%d", len(removed))

    if not file_blocks:
        logger.warning(
            "prompt_truncation_stripped_all_files preamble_tokens=%d target=%d",
            preamble_tokens, target_tokens,
        )
    result = preamble + ("\n\n" + "\n\n".join(file_blocks) if file_blocks else "")
    removed_count = len(parts) - 1 - len(file_blocks)
    if removed_count > 0:
        result += f"\n\n[... {removed_count} file(s) removed to fit context window ...]"
    logger.info("prompt_truncated original=%d target=%d files_removed=%d", estimated_tokens, target_tokens, removed_count)
    return result


_MAX_SOURCE_CHARS = _safe_int_env("VULTURE_MAX_SOURCE_CHARS", 400000)

# Feature 0070 P5 (A.4): ceiling applied when a window is a GUESS *and* a custom
# gateway is in play. Numerically equal to DEFAULT_CONTEXT_WINDOW (32K) today;
# named separately and env-tunable because the two mean different things — one is
# "what we assume when we know nothing", the other is "the most we will trust a
# guess with when sizing a real request body". Behind a gateway only three
# sources are authoritative: an explicit VULTURE_LLM_CTX_SIZE, the broker
# registry (§31), or an exact CONTEXT_WINDOWS match. A family guess is not, so a
# known family behind a gateway is deliberately clamped too — the gateway may
# proxy a smaller window than the upstream model offers, and we cannot tell.
_GATEWAY_GUESS_CEILING = _safe_int_env("VULTURE_LLM_GATEWAY_GUESS_CTX", 32_000)

# Feature 0070 P5 (defect A): our source budget is denominated in TOKENS, but a
# gateway rejects on BYTES ("request_too_large" / HTTP 413). The two disagree by
# a factor that depends on the content, so a token budget alone cannot keep the
# request inside a byte limit — a 131,072-token window resolved to 196,608 chars
# (~192KB) of inlined source and the gateway refused the whole phase.
# VULTURE_LLM_MAX_BODY_BYTES is an ADDITIONAL ceiling enforced on the encoded
# payload (len(text.encode())), never on the character count.
# 128 KB, not 256 KB. The observed 413 carried ~192KB of inlined source, so a
# 256KB ceiling would never have fired on the very request that motivated this
# cap — it has to sit BELOW the failure, not above it. 128KB still admits ~30-40
# source files per batch, and the batch loop rolls the remainder into the next
# request rather than dropping it, so a lower ceiling costs latency, not coverage.
_DEFAULT_MAX_BODY_BYTES = 131072  # 128 KB
# Bytes reserved for the truncation notice appended to a capped body.
_BODY_TRUNCATION_NOTICE_BYTES = 128

_FILE_BLOCK_HEADER_RE = re.compile(r"(?m)^--- .+ ---$")

# Warn once per process (not per run) when the loop guard cannot be attached.
_LOOP_GUARD_WARNED = False


def _get_max_body_bytes() -> int:
    """Encoded-payload ceiling for the LLM request body, in bytes.

    ``VULTURE_LLM_MAX_BODY_BYTES`` (default 128KB); <= 0 disables the cap.
    """
    return _safe_int_env("VULTURE_LLM_MAX_BODY_BYTES", _DEFAULT_MAX_BODY_BYTES)


def _max_consecutive_failures() -> int:
    """Feature 0070 P5 (D.2): abort the LLM phase after N consecutive batch
    failures. 0 disables.

    CONSECUTIVE, not cumulative: a cumulative counter would abort a long sweep
    that merely had a few unlucky batches spread across it, while consecutive
    failure is the signal for something SYSTEMIC — a dead gateway, a body limit,
    bad credentials. Measured on a gateway that 413s everything: 19 batches each
    burned their full attempt budget for 625 HTTP calls; aborting at 3 cuts that
    by ~84%.
    """
    return max(0, _safe_int_env("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", 3))


def _max_turns() -> int:
    """Feature 0070 P5 (D.3): cap the SDK agent loop's turns per attempt.

    `Runner.run` was called with no `max_turns`, so one attempt could issue an
    unbounded number of model calls — measured at ~16 per attempt, none of it
    visible to `retry_llm_call`'s budget. The tool-loop guard does not cover this:
    it counts TOOL calls, and a turn that produces no tool call is invisible to it.
    """
    return max(1, _safe_int_env("VULTURE_LLM_MAX_TURNS", 12))


_RETRIES_PINNED = False


def _pin_llm_client_retries() -> None:
    """Feature 0070 P5 (D.1): belt-and-braces ONLY — this is not the retry guard.

    Read this before trusting it. Setting the module attributes does NOT bound
    chat-completion retries, and that was MEASURED, not inferred: against a stub
    gateway answering 429, one logical completion still made **3 HTTP attempts**
    with this function applied. See
    `tests/unit/test_0070_p5_d1_retry_pin.py`, which stands the stub up and
    counts.

    Why it cannot work: `litellm.main.completion` reads `max_retries` from
    per-call kwargs only; `litellm.num_retries` is consulted on the speech and
    transcription paths, never on chat completions. The one surviving module
    read is `litellm.num_retries or openai.DEFAULT_MAX_RETRIES` — and `0` is
    FALSY, so pinning the attribute to zero selects the default (2, i.e. 3
    attempts) that it was meant to suppress.

    The hazard it was aimed at is real, and `broker.py` names it exactly while
    bounding its own AsyncOpenAI client: "broker 3x x SDK 2x x agent
    retry_llm_call 3x". That guard is unreachable off the broker path — with
    OPENAI_BASE_URL set and the broker off, `get_model()` returns
    `litellm/openai/<model>` and the SDK takes its LiteLLM path instead.
    Measured (litellm 1.87.1): `litellm.num_retries` is None — litellm's own
    retry wrapper is off — but `openai._base_client.DEFAULT_MAX_RETRIES` is 2
    underneath, a hidden 3x on any retryable status (408/409/429/500). A 413 is
    not in that set, which is why the observed 413 was not inflated; a 429 would
    have been, giving 9 attempts where 3 were intended.

    The ACTUAL guard is `provider.litellm_retry_extra_args()`, which puts
    `max_retries=0` on the call itself via `ModelSettings.extra_args`. This
    function is retained because it costs nothing, still covers the non-chat
    litellm surfaces, and pins `litellm.DEFAULT_MAX_RETRIES` where the version
    exposes it — but on its own it buys zero attempts back on the audit path.

    Idempotent, and never fatal: a litellm that does not expose these attributes
    must not break the audit.
    """
    global _RETRIES_PINNED
    if _RETRIES_PINNED:
        return
    try:
        import litellm

        litellm.num_retries = 0
        # Also pin the underlying client default where the version exposes it.
        if hasattr(litellm, "DEFAULT_MAX_RETRIES"):
            litellm.DEFAULT_MAX_RETRIES = 0
        _RETRIES_PINNED = True
        logger.debug("llm_client_retries_pinned num_retries=0")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("llm_client_retries_pin_skipped: %s", exc)


# Settings that only the SDK's LiteLLM model can carry through to the provider
# call. `OpenAIChatCompletionsModel` splats `extra_args` into the openai SDK's
# `create()`, whose generated signature accepts neither of these nor `**kwargs`.
_LITELLM_ONLY_EXTRA_ARGS = ("max_retries", "num_retries")


def _drop_litellm_only_settings(settings: dict, *, broker_active: bool) -> dict:
    """Strip LiteLLM-only `extra_args` when the run is NOT on the LiteLLM path.

    Feature 0070 P5 (D.1). `get_model_settings()` gates the retry pin on the
    resolved model prefix and the `VULTURE_LLM_BROKER` env var, but the env var
    is not the runtime truth: the broker also needs a URL and a per-run token,
    and only `_run_llm_agent` knows whether `broker_model_provider()` actually
    built a provider. When it did, `RunConfig` routes through an OpenAI client
    whatever the model string says, so the pin would be a TypeError rather than
    a no-op. The runner's answer wins here.

    Returns a copy; the caller's dict is never mutated.
    """
    if not broker_active:
        return settings
    extra = settings.get("extra_args")
    if not isinstance(extra, dict):
        return settings
    trimmed = {k: v for k, v in extra.items() if k not in _LITELLM_ONLY_EXTRA_ARGS}
    out = dict(settings)
    if trimmed:
        out["extra_args"] = trimmed
    else:
        out.pop("extra_args", None)
    return out


def _require_loop_guard() -> bool:
    """Feature 0070 P5 (C.3): refuse the LLM phase without a tool loop guard."""
    return os.environ.get("VULTURE_REQUIRE_LOOP_GUARD", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _truncate_utf8(text: str, max_bytes: int) -> str:
    """Cut *text* to at most *max_bytes* encoded bytes without splitting a char."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _split_source_blocks(text: str) -> list[str]:
    """Split packed source context back into its ``--- rel ---`` file blocks."""
    starts = [m.start() for m in _FILE_BLOCK_HEADER_RE.finditer(text)]
    if not starts:
        return [text]
    blocks: list[str] = []
    if starts[0] > 0:
        head = text[: starts[0]].strip("\n")
        if head:
            blocks.append(head)
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(text)
        blocks.append(text[start:end].strip("\n"))
    return blocks


def _enforce_body_byte_cap(
    text: str, max_bytes: int = 0, label: str = "source_context",
) -> str:
    """Cap *text* at the encoded-byte ceiling, dropping whole trailing files.

    Truncation is reported in the same shape as the scanner's ``scan_truncated``
    warning: a partial LLM body must never be indistinguishable from a full one.
    """
    if not text:
        return text
    if max_bytes <= 0:
        max_bytes = _get_max_body_bytes()
    if max_bytes <= 0:
        return text
    total = len(text.encode("utf-8"))
    if total <= max_bytes:
        return text

    budget = max(0, max_bytes - _BODY_TRUNCATION_NOTICE_BYTES)
    blocks = _split_source_blocks(text)
    kept: list[str] = []
    used = 0
    for block in blocks:
        cost = len(block.encode("utf-8")) + (2 if kept else 0)
        if used + cost > budget:
            break
        kept.append(block)
        used += cost
    if not kept:
        # A single file bigger than the whole budget: keep a byte-bounded head
        # rather than sending nothing.
        kept = [_truncate_utf8(blocks[0], budget)]
    dropped = len(blocks) - len(kept)
    out = "\n\n".join(kept)
    if dropped > 0:
        out += f"\n\n[... {dropped} file(s) dropped: request body cap {max_bytes} bytes ...]"
    logger.warning(
        "llm_body_truncated label=%s bytes=%d max=%d files_dropped=%d kept=%d — "
        "coverage is PARTIAL; raise VULTURE_LLM_MAX_BODY_BYTES if the gateway "
        "accepts larger requests",
        label, total, max_bytes, dropped, len(kept),
    )
    return out


def _halve_source_context(source_context: str) -> str:
    """Half-size the inlined source body for the one-shot size retry (A.2).

    Returns "" when there is nothing meaningful left to halve (no inline source,
    or already at the floor) — the caller then degrades instead of retrying.
    """
    if not source_context:
        return ""
    current = len(source_context.encode("utf-8"))
    target = current // 2
    if target < 512:
        return ""
    smaller = _enforce_body_byte_cap(source_context, max_bytes=target, label="size_retry")
    if not smaller or smaller == source_context:
        return ""
    return smaller


def _get_max_source_chars(model: str | None = None) -> int:
    """Compute max source chars from the active model's context window.

    Uses ``get_context_window()`` (env override > model lookup > 32K default).
    The OpenAI Agents SDK adds significant overhead (tool schemas, structured
    output schema, system instructions) — typically 3-5K tokens.  We reserve
    50% of context for source code at ~3 chars per token (code is token-dense).

    The result is capped at ``_MAX_SOURCE_CHARS`` (default 400K, configurable
    via ``VULTURE_MAX_SOURCE_CHARS``) to prevent unbounded memory usage with
    large-context models like Gemini (1M+ tokens).

    Args:
        model: Optional model key. Defaults to VULTURE_LLM_MODEL env.
    """
    from shared.llm.provider import (
        WINDOW_FROM_DEFAULT,
        WINDOW_FROM_FAMILY,
        resolve_context_window,
        uses_custom_endpoint,
    )

    ctx_tokens, provenance = resolve_context_window(model)
    # Feature 0070 P5 (defect A.4, reworked): behind a custom gateway an
    # unknown model's window is a GUESS made from a substring of its id
    # (`glm-5-2-260617` → the "glm" family → 131072 tokens → 196,608 chars ≈
    # 192KB inlined, which the gateway rejected outright). §31 keeps that guess
    # for token *budgeting* — three tests pin it, and undershooting the window
    # would shrink max_output too — but it must not be trusted to size a
    # REQUEST BODY. Authoritative windows (explicit env, broker registry, exact
    # table) are used as-is; only the inferred-behind-a-gateway case undershoots.
    # Both non-authoritative provenances qualify. A bare DEFAULT is a *stronger*
    # guess than a family match, not a weaker one: the model id matched nothing at
    # all. `glm-5-2-260617` resolves that way, so guarding only FAMILY left the
    # exact model from the observed 413 unclamped.
    _guessed = provenance in (WINDOW_FROM_FAMILY, WINDOW_FROM_DEFAULT)
    if _guessed and uses_custom_endpoint() and ctx_tokens > _GATEWAY_GUESS_CEILING:
        logger.warning(
            "llm_body_window_clamped model=%s inferred=%d using=%d "
            "hint=set VULTURE_LLM_CTX_SIZE to the gateway's real window",
            model or os.environ.get("VULTURE_LLM_MODEL", ""),
            ctx_tokens, _GATEWAY_GUESS_CEILING,
        )
        ctx_tokens = _GATEWAY_GUESS_CEILING
    # Scale source allocation: small models need more headroom for output + SDK overhead.
    source_fraction = 0.35 if ctx_tokens <= 32_000 else 0.5
    # Cap: read VULTURE_MAX_SOURCE_CHARS dynamically (feature 0057 P1f — tests
    # and operators tune the per-batch budget at runtime) so the batch loop's
    # window size honours the env without an import-time freeze. Falls back to
    # the module default when unset.
    cap = _safe_int_env("VULTURE_MAX_SOURCE_CHARS", _MAX_SOURCE_CHARS)
    # NOTE (feature 0070 P5, A.1): the byte ceiling is deliberately NOT folded in
    # here. This function returns a CHARACTER budget, and one char is 1-4 bytes:
    # a char cap can never enforce a byte limit. VULTURE_LLM_MAX_BODY_BYTES is
    # enforced where it can be measured — on the encoded payload, in
    # _enforce_body_byte_cap() — so the two budgets stay honest about their units.
    # ~3 chars per token for code. Safety margin applied later by safe_estimate_tokens().
    return min(max(2000, int(ctx_tokens * source_fraction * 3)), cap)


def _safe_stat_size(p: Path) -> int:
    """Get file size with a single syscall; return 0 on any OS error."""
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _safe_rel(fpath: Path, source_path: str) -> str:
    """Compute relative path safely, falling back to str(fpath)."""
    try:
        return str(fpath.relative_to(source_path))
    except ValueError:
        return str(fpath)


def _prioritize_files(
    files: list,
    source_path: str,
    skill_findings: list[dict] | None = None,
    include_tier3: bool = True,
) -> list:
    """Sort files into priority tiers for LLM context packing.

    Tier 1: Files that appear in skill_findings (highest signal).
    Tier 2: Entry points and config files (structural importance).
    Tier 3: Remaining files, sorted by size ascending (smaller = more likely focused).

    Feature 0059: when ``include_tier3`` is False, Tier 3 is dropped entirely
    (the LLM sees only flagged + entry/config files) — the cost guard. The
    deterministic phase is upstream and unaffected: skills/signatures still
    scan every file regardless.

    Args:
        files: List of Path objects from scan_code_files.
        source_path: Root directory (used for relative path matching).
        skill_findings: Optional skill findings to prioritize by.

    Returns:
        Reordered list of Path objects.
    """
    finding_paths: set[str] = set()
    if skill_findings:
        for f in skill_findings:
            fp = f.get("file_path", "")
            if fp:
                finding_paths.add(fp)
                # Also store relative form for matching
                if fp.startswith(source_path):
                    rel = fp[len(source_path):].lstrip("/")
                    finding_paths.add(rel)

    tier1: list = []
    tier2: list = []
    tier3: list = []

    for fpath in files:
        fstr = str(fpath)
        rel = _safe_rel(fpath, source_path)
        if fstr in finding_paths or rel in finding_paths:
            tier1.append(fpath)
        elif is_entry_or_config(Path(fpath) if not isinstance(fpath, Path) else fpath):
            tier2.append(fpath)
        else:
            tier3.append(fpath)

    if not include_tier3:
        return tier1 + tier2

    # Sort tier3 by file size ascending (smaller files first)
    # Pre-compute stat results to avoid repeated syscalls during sort comparisons
    size_map = {p: _safe_stat_size(p) for p in tier3}
    tier3.sort(key=lambda p: size_map[p])

    return tier1 + tier2 + tier3


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping (start, end) ranges into non-overlapping spans."""
    if not ranges:
        return []
    ranges.sort()
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


# Head-block size for findings that sit at the top of a file. Deliberately its
# own constant, NOT derived from the snippet width: coupling them would change
# today's output at the default width (T3.6).
_LINE1_HEAD_LINES = 30

# Default lines of context each side of a finding. P3's width knob; the default
# reproduces pre-0075 output byte-for-byte, so the feature ships inert.
_DEFAULT_SNIPPET_CONTEXT = 10


def _snippet_context_lines() -> int:
    """Resolved snippet half-window. ``VULTURE_LLM_SNIPPET_CONTEXT`` widens it.

    A wider window costs budget (fewer files per batch) and buys the model the
    guard that refutes a finding — measured as `guard_present` false positives
    where the mitigation sat outside the window. Not raised by default in this
    feature; the knob exists so the tradeoff can be measured.
    """
    return _safe_int_env("VULTURE_LLM_SNIPPET_CONTEXT", _DEFAULT_SNIPPET_CONTEXT)


def _whole_file_max_lines() -> int:
    """Files at or below this many lines are rendered whole instead of windowed.

    ``0`` (the ship default) disables the mode entirely, so P3 is inert. For a
    small file the elision markers cost nearly as much as the omitted lines and
    remove the surrounding context that decides whether a finding is real.
    """
    return _safe_int_env("VULTURE_LLM_WHOLE_FILE_MAX_LINES", 0)


def _split_content_lines(content: str) -> list[str]:
    """Split file text into its REAL lines.

    ``"a\\nb\\n".split("\\n")`` yields a trailing ``""``, which rendered as a
    phantom ``"3: "`` in every numbered file — inviting the model to cite a line
    that does not exist, and invisible to a ``^\\d+: `` check because the phantom
    matches it. Only the final empty element is dropped, and only when the text
    actually ends in a newline: a file with no trailing newline keeps its last
    line, because deleting it would delete any defect sitting there.
    """
    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _group_findings_by_path(skill_findings: list[dict] | None) -> dict[str, list[dict]]:
    """Index findings by ``file_path``. One grouper, used by both feed paths."""
    grouped: dict[str, list[dict]] = {}
    for f in skill_findings or []:
        fp = f.get("file_path", "")
        if fp:
            grouped.setdefault(fp, []).append(f)
    return grouped


# Feature 0076 T0.1: the write direction moved VERBATIM to the leaf
# ``shared/tools/line_format.py`` so ``tools/file_reader.py`` can number what it
# hands the model without importing ``audit_runner`` (which closes the
# ``audit_runner -> shared.tools.* -> __init__ -> file_reader -> audit_runner``
# cycle, §5.0 D16). The name is kept as an ALIAS — the same function object, not
# a wrapper — so every 0075 caller and structural guard is untouched and the two
# cannot drift.
_number_lines = line_format.number_lines


def _line_numbers_enabled() -> bool:
    """Whether to number files that carry no usable skill-finding line info.

    Feature 0075 rollback switch. It governs ONLY the numbering this feature adds
    (a whole file, or a findings-bearing file whose findings have no line numbers).
    Snippet numbering predates 0075 and is unconditional — turning this off restores
    the pre-0075 presentation exactly, no more.
    """
    return env_flag("VULTURE_LLM_LINE_NUMBERS", True)


# The LLM feed's extension set lives in file_scanner.py beside the scanner's own sets
# (feature 0075 T2.10 / DRY). Re-exported under the old private name so existing
# call sites and tests keep working.
from shared.tools.file_scanner import (  # noqa: E402
    llm_feed_extensions as _llm_feed_extensions,
)


def _present_source(content: str) -> str:
    """Format a whole file for prompt inclusion.

    The model is asked to report ``line_start`` for every finding. Presented raw it
    can only count newlines, and it is bad at that: measured across 108 adjudicated
    findings, files presented raw mislocated 25 of 32 (78%) against 5 of 38 (13%)
    for numbered ones, and precision was 12.5% against 44.7%. The tier's unique
    value is in files no skill flagged — precisely the files this used to hand over
    blind.
    """
    if not _line_numbers_enabled():
        return content
    return _number_lines(_split_content_lines(content))


def _extract_file_snippet(
    content: str,
    findings: list[dict],
    rel_path: str,
    context_lines: int | None = None,
) -> str:
    """Extract relevant code snippets from a file based on finding line ranges.

    Args:
        content: Full file content.
        findings: Findings that reference this file.
        rel_path: Relative path for matching.
        context_lines: Lines of context around each finding.

    Returns:
        Snippet text covering all finding ranges, or full content if no lines.
    """
    return _present_findings_snippet(content, findings, rel_path, context_lines)


def _snippet_ranges(
    findings: list[dict], rel_path: str, line_count: int, context_lines: int,
) -> list[tuple[int, int]]:
    """Half-open ``[start, end)`` windows, one per finding that names this file.

    Findings with no usable ``line_start`` contribute nothing, so an empty result
    means "this file has findings but none can be located".
    """
    ranges: list[tuple[int, int]] = []
    for f in findings:
        fp = f.get("file_path", "")
        if not fp.endswith(rel_path) and rel_path not in fp:
            continue
        ls = f.get("line_start", 0)
        le = f.get("line_end", 0) or ls
        if ls > 0:
            ranges.append((max(0, ls - 1 - context_lines), min(line_count, le + context_lines)))
    return ranges


def _present_findings_snippet(
    content: str, findings: list[dict], rel_path: str, context_lines: int | None,
) -> str:
    """Render the windows around a file's findings, numbered absolutely."""
    # An explicit argument wins; otherwise resolve the env-configured width. The
    # resolved default equals the historical literal 10, so output is unchanged.
    if context_lines is None:
        context_lines = _snippet_context_lines()
    lines = _split_content_lines(content)
    # Whole-file mode (P3, inert at the 0 default): for a small file the elision
    # markers cost nearly what the omitted lines would, and windowing removes the
    # surrounding context that decides whether a finding is real.
    whole = _whole_file_max_lines()
    if whole > 0 and len(lines) <= whole:
        return _number_lines(lines)
    ranges = _snippet_ranges(findings, rel_path, len(lines), context_lines)
    if not ranges:
        # No usable line info — include the full file, NUMBERED (0075). This path
        # returned raw text, so a file could carry skill findings and still be
        # presented blind; the model then had nothing to cite from.
        return _present_source(content)
    # When every range starts at the top of the file, render a head block rather
    # than a window — more useful context for a line-1 finding.
    #
    # The head must reach at least as far as the widest range end, or widening
    # `context_lines` REMOVES lines: a finding at line 26 with context 25 drives
    # the start to 0, trips this branch, and truncated to the first 30 lines —
    # dropping 31-36 that context 10 had rendered. Widening a window must always
    # be a superset (T3.2b). `_LINE1_HEAD_LINES` stays its own constant rather
    # than tracking the width, so `ls=1, context=10` is byte-identical to
    # pre-0075 output (T3.6).
    if all(s == 0 for s, _e in ranges):
        head = max(_LINE1_HEAD_LINES, max(e for _s, e in ranges))
        return _number_lines(lines, 0, min(head, len(lines)))
    merged = _merge_ranges(ranges)
    return "\n...\n".join(_number_lines(lines, start, end) for start, end in merged)


def _omitted_ranges(findings: list[dict], rel_path: str, line_count: int,
                    context_lines: int | None = None) -> list[tuple[int, int]]:
    """1-based inclusive line ranges a windowed render leaves OUT.

    Feature 0075 T3.5. A bare ``...`` tells the model something was cut but not what,
    so it cannot judge whether the construct it wants is inside the gap. Naming the
    gaps costs one line per file. The label goes in the HEADER, never on the marker:
    ``numbered_line_fraction`` skips a line whose stripped form is exactly ``...``, so
    labelling the marker itself would make every elided file look partly unnumbered
    and quietly corrupt the coverage metric (T3.5b).
    """
    if context_lines is None:
        context_lines = _snippet_context_lines()
    ranges = _snippet_ranges(findings, rel_path, line_count, context_lines)
    if not ranges:
        return []
    if all(s == 0 for s, _e in ranges):
        head = min(max(_LINE1_HEAD_LINES, max(e for _s, e in ranges)), line_count)
        return [(head + 1, line_count)] if head < line_count else []
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in _merge_ranges(ranges):
        if start > cursor:
            gaps.append((cursor + 1, start))
        cursor = max(cursor, end)
    if cursor < line_count:
        gaps.append((cursor + 1, line_count))
    return gaps


def _block_header(rel: str, omitted: list[tuple[int, int]]) -> str:
    """``--- rel ---``, or ``--- rel (lines 1-9, 31-89 omitted) ---`` when windowed.

    Must keep the ``^--- .+ ---$`` shape: ``_FILE_BLOCK_HEADER_RE`` (:349) segments
    batches on it and the probe splits on ``"\n\n--- "``. A suffix inside the
    delimiters satisfies both (T3.5b).
    """
    if not omitted:
        return f"--- {rel} ---"
    spans = ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in omitted)
    return f"--- {rel} (lines {spans} omitted) ---"


def _pack_files(
    ordered_files: list,
    source_path: str,
    max_chars: int,
    skill_findings: list[dict] | None = None,
) -> tuple[str, list[str]]:
    """Pack files into a formatted string within the character budget.

    Uses snippet extraction for files with findings (sends only relevant
    code + context lines). Includes full content for entry points/configs.

    Args:
        ordered_files: Priority-ordered list of Path objects.
        source_path: Root directory for relative path computation.
        max_chars: Maximum total characters to include.
        skill_findings: Optional findings for snippet extraction.

    Returns:
        Tuple of (formatted string, list of relative paths included).
    """
    parts: list[str] = []
    included_paths: list[str] = []
    total = 0
    dropped = 0
    # One reader, one presenter, one grouper: this used to duplicate
    # _format_file_block's four branches verbatim, so a presentation fix applied to
    # one path silently missed the other — which is exactly how the unnumbered
    # branch survived in both (0075 T1.12).
    findings_by_path = _group_findings_by_path(skill_findings)
    for fpath in ordered_files:
        block = _format_file_block(fpath, source_path, findings_by_path)
        if block is None:
            continue
        rel, text = block
        entry_len = len(text) + 2
        if total + entry_len > max_chars:
            dropped += 1
            continue
        parts.append(text)
        included_paths.append(rel)
        total += entry_len

    if dropped:
        # Numbering costs ~5-7 chars per line, so fewer files fit a fixed budget.
        # That is a real coverage reduction and must never be silent (0075 T1.13).
        logger.warning(
            "llm_pack_dropped files=%d included=%d budget=%d — coverage is PARTIAL; "
            "raise VULTURE_MAX_SOURCE_CHARS or VULTURE_LLM_MAX_BODY_BYTES",
            dropped, len(included_paths), max_chars,
        )

    if not parts:
        return "", []
    return "\n\n".join(parts), included_paths


# Feature 0057 P1f: per-batch file cap so a single batch can't pack the whole
# tree when files are tiny (keeps batches bounded by file count too, not only
# by char budget). The USD budget + context window remain the real throttles.
_LLM_FILES_PER_BATCH = _safe_int_env("VULTURE_LLM_FILES_PER_BATCH", 40)


def _format_file_block(
    fpath: Any,
    source_path: str,
    findings_by_path: dict[str, list[dict]],
) -> tuple[str, str] | None:
    """Format one file into a ``(rel_path, "--- rel ---\\ncontent")`` block,
    using snippet extraction for files that carry skill findings. Returns None
    when the file is empty / unreadable."""
    content = read_file_safe(fpath)
    if content is None or not content.strip():
        return None
    rel = _safe_rel(fpath, source_path)
    if findings_by_path:
        file_findings = findings_by_path.get(rel, [])
        if not file_findings:
            file_findings = [
                f for fp_key, flist in findings_by_path.items()
                for f in flist
                if fp_key.endswith(rel)
            ]
        if file_findings:
            omitted = _omitted_ranges(
                file_findings, rel, len(_split_content_lines(content)),
            )
            content = _extract_file_snippet(content, file_findings, rel)
        else:
            omitted = []
            content = _present_source(content)
    else:
        omitted = []
        content = _present_source(content)
    return rel, f"{_block_header(rel, omitted)}\n{content}"


def _llm_eligible_files(files: list) -> list:
    """Files the LLM tier may analyse.

    The single place this rule lives. Every skill filters test and generated
    files; the LLM tier did not, so the model was handed exploit tests that
    *demonstrate* a weakness and reported it there — right vulnerability, wrong
    file, and unactionable. Measured: 9 of 22 LLM findings on one target were
    test-file artefacts, two of which passed the L5 judge.

    There are TWO paths that feed files to the model — the single-shot context
    and the batched sweep — and fixing only the first left 5 of the artefacts in
    place. Hence one helper rather than two call-site filters.
    """
    return [f for f in files if not is_test_file(f) and not is_generated_file(f)]


def _build_source_batches(
    ordered_files: list,
    source_path: str,
    max_chars: int,
    skill_findings: list[dict] | None = None,
    files_per_batch: int = _LLM_FILES_PER_BATCH,
) -> list[tuple[str, list[str]]]:
    """Partition the ordered file list into context-window-sized batches.

    Feature 0057 P1f: the LLM phase sweeps the WHOLE tree by iterating over
    these batches, instead of a single context window that silently tail-drops
    the rest. Each batch's packed text is ≤ ``max_chars`` and holds ≤
    ``files_per_batch`` files. A single file larger than the whole budget still
    gets its own (over-budget) batch so it is never dropped — truncation to the
    real context window happens later per call.

    Returns a list of ``(batch_text, included_relpaths)``; empty if no files.
    """
    findings_by_path = _group_findings_by_path(skill_findings)

    batches: list[tuple[str, list[str]]] = []
    cur_parts: list[str] = []
    cur_paths: list[str] = []
    cur_total = 0

    def _flush() -> None:
        nonlocal cur_parts, cur_paths, cur_total
        if cur_parts:
            batches.append(("\n\n".join(cur_parts), cur_paths))
            cur_parts, cur_paths, cur_total = [], [], 0

    for fpath in ordered_files:
        block = _format_file_block(fpath, source_path, findings_by_path)
        if block is None:
            continue
        rel, text = block
        entry_len = len(text) + 2
        # Start a new batch when the current one is full (by chars or count)
        # — but never emit an empty batch just because one file is huge.
        if cur_parts and (
            cur_total + entry_len > max_chars
            or len(cur_paths) >= files_per_batch
        ):
            _flush()
        cur_parts.append(text)
        cur_paths.append(rel)
        cur_total += entry_len
    _flush()
    return batches


def _build_source_context(
    source_path: str,
    max_chars: int = 0,
    skill_findings: list[dict] | None = None,
    model: str | None = None,
) -> str:
    """Pre-read source files and format them for inline LLM prompt inclusion.

    Local models (Ollama, LM Studio) often lack function-calling support,
    so they cannot use tools to read files.  This function scans the source
    tree and embeds file contents directly in the prompt so the LLM can
    analyze the code without tool use.

    Files are prioritized: skill-finding files first, then entry points/config,
    then remaining files sorted by size ascending.  Files with skill findings
    use snippet extraction (finding lines + context) instead of full content.

    Args:
        source_path: Root directory of the source code.
        max_chars: Maximum total characters of source code to include.
        skill_findings: Optional skill findings for file prioritization and snippets.
        model: Optional model key for context window sizing.

    Returns:
        Formatted string with file contents, or empty string if no files found.
    """
    if max_chars <= 0:
        max_chars = _get_max_source_chars(model)
    # ONE resolved set for both feed paths. This site named bare CODE_EXTENSIONS
    # while the batched sweep named the wide default, so the two paths that feed
    # the same model disagreed about which files are code — the original RC3
    # defect. Naming the same helper is the fix; a structural test that merely
    # checks both sites *name* `extensions=` cannot see the disagreement, so the
    # guard asserts the resolved sets are EQUAL.
    files = scan_code_files(source_path, extensions=_llm_feed_extensions())
    # Every skill filters test and generated files; this phase did not, so the
    # model was handed exploit tests that *demonstrate* a weakness and reported
    # it there — right vulnerability, wrong file, and unfixable by the reader.
    # Measured on one target: 9 of 22 LLM findings were test-file artefacts, two
    # of which even passed the L5 judge. The two tiers must agree on what counts
    # as code under review.
    files = _llm_eligible_files(files)
    if not files:
        return ""

    ordered = _prioritize_files(files, source_path, skill_findings)
    text, _paths = _pack_files(ordered, source_path, max_chars, skill_findings)
    # Feature 0070 P5 (A.1): the pack budget is in chars; the gateway rejects on
    # bytes. Enforce the encoded ceiling before this ever becomes a request.
    return _enforce_body_byte_cap(text, label="build_source_context")


def _normalize_dedup_path(fp: str, source_path: str = "") -> str:
    """Normalize a finding path to a canonical *source-root-relative* token so
    absolute and source-relative forms of the SAME file collapse to one dedup
    key — WITHOUT collapsing two genuinely different files that merely share a
    basename.

    Feature 0057 P1f: the LLM phase reports repo-RELATIVE paths (``src/app.py``)
    while skills report ABSOLUTE paths (``/repo/src/app.py``) for the same file.
    Earlier this used a basename fallback, which was wrong in two ways:
      * over-dedup (data loss): ``a/util.py`` and ``b/util.py`` both collapsed
        to ``util.py`` → a real net-new finding in a different directory was
        dropped as a duplicate;
      * under-dedup (double-report): an LLM dupe at ``src/app.py`` (→ basename
        ``app.py``) did not match the skill's root-stripped ``src/app.py``, so
        the same vuln surfaced twice.

    Fix: normalise BOTH forms to a source-root-relative path. Absolute paths
    under the root are made relative; already-relative paths are normalised
    in place (and only resolved against the root when that actually locates
    the file, so we never invent a wrong directory). The directory structure
    is preserved, so distinct directories stay distinct.
    """
    if not fp:
        return ""
    # Backward-compat: when no source root is known (direct unit-test calls),
    # preserve the exact path so the historical (check_id, file_path) key is
    # unchanged. Normalization only kicks in for the real audit pipeline,
    # which always passes source_path.
    if not source_path:
        return fp

    root = source_path.rstrip("/")
    # Absolute path under the root → strip the root, keep the full subpath.
    if fp.startswith(root):
        rel = fp[len(root):].lstrip("/")
        return os.path.normpath(rel) if rel else ""
    # Already source-relative (the LLM's normal output): normalise in place,
    # stripping any leading "./". Keep the FULL relative path (not the
    # basename) so same-basename files in different directories stay distinct.
    cleaned = fp.lstrip("/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return os.path.normpath(cleaned) if cleaned else ""


def _dedup_key(f: dict, source_path: str = "") -> tuple[str, str]:
    """Build dedup key preferring check_id over normalized title.

    The path component is normalized (P1f) so absolute vs relative forms of
    the same file do not defeat cross-phase dedup.
    """
    # 0076 AC26: ``_model_check_id`` is the identity a stripped model-authored
    # ``check_id`` left behind. Falling back to it BEFORE the normalised title is
    # what makes the strip count-neutral — without it the row re-keys onto
    # (title, path) and a colliding skill row deletes it.
    cid = f.get("check_id", "") or f.get("_model_check_id", "")
    fp = _normalize_dedup_path(f.get("file_path", ""), source_path)
    if cid:
        return (cid, fp)
    return (_normalize_title(f.get("title", "")), fp)


# ── Feature 0076 §5.4: the anchor stamp, the egress strip, and the survivor merge ──

# Every field the verifier stamps, plus the two model-authored strings the parser
# preserves for internal use. ONE roster, deleted by ONE pass. Adding a tenth
# private field without adding it here is how the next leak happens.
_PRIVATE_FIELDS = ("evidence_quote", "_model_check_id", "_anchor_status",
                   "_anchor_reason",
                   "_claimed_line", "_anchor_delta", "_anchor_candidates",
                   "_anchor_other_path", "_anchor_quote_chars",
                   "_anchor_quote_tokens")

# The fields a dedup survivor adopts from a better-anchored row (AC30). The
# status without its provenance cannot be audited or re-measured, so the delta,
# the candidate count and the cross-file path travel with it.
_ADOPTED_ANCHOR_FIELDS = ("_anchor_status", "_anchor_delta",
                          "_anchor_candidates", "_anchor_other_path")

# The total quality order the survivor merge resolves against; higher wins.
# ``unquoted``/``oversize`` and ``unreadable``/``absent`` share a rank because
# neither of each pair carries information the other lacks.
_ANCHOR_QUALITY = {
    "exact": 6, "reanchored": 5, "near_miss": 4, "found_elsewhere": 3,
    "ambiguous": 2, "unquoted": 1, "oversize": 1, "unreadable": 0, "absent": 0,
}


# The subset that must die at the PARSE choke point, before any mode check:
# `evidence_quote` is model-copied source that can carry a live credential, and
# `_model_check_id` is only needed to keep the dedup identity stable across the
# strip. The `_anchor_*` stamps are NOT here — `run_l1` is their last consumer
# (validate/__init__._strip_private removes them afterwards), and deleting them
# at parse time makes the whole feature inert: no `anchor` check is ever emitted.
_PARSE_PRIVATE_FIELDS = ("evidence_quote", "_model_check_id")


def _public_view(finding: dict) -> dict:
    """The finding as a consumer outside this process may see it.

    `emitter.finding_event(**_public_view(finding))` forwards `**extra` VERBATIM and the SSE
    emit happens BEFORE the validate stage runs, so a private stamp still in
    flight would reach the live stream while Go's fixed `model.Finding` dropped
    it — one finding with two different contents depending on when you looked.
    Filtering at the CALL SITE rather than inside the emitter keeps the
    emitter's documented forward-everything contract intact and makes every
    future underscore-prefixed stamp safe without a roster entry.
    """
    return {k: v for k, v in finding.items() if not k.startswith("_")}


def _strip_private_fields(
    finding: dict, fields: tuple[str, ...] = _PRIVATE_FIELDS,
) -> None:
    """Delete every private field. Mutates in place, returns None, idempotent.

    Called UNCONDITIONALLY on every parsed LLM finding at the parse choke point —
    before any mode check, and regardless of ``VULTURE_LLM_QUOTE_VERIFY``.

    An earlier draft called this from inside the verifier. At
    ``VULTURE_LLM_QUOTE_VERIFY=off`` the verifier does not run, so
    ``evidence_quote`` — model-copied source that can contain a live credential —
    flowed straight to SSE, to the DB and into the L5 prompt. The rollback path
    walked directly through that hole: an operator disabling the feature after an
    incident would have ENABLED the leak.

    The seven ``_anchor_*`` stamps are private for a second, quieter reason:
    ``emitter.finding_event(**_public_view(finding))`` forwards ``**extra`` verbatim, so plain
    names would reach the live stream and then be dropped at Go's fixed
    ``model.Finding`` boundary — one finding with two different contents
    depending on whether you watched it live or replayed it.
    """
    for name in fields:
        finding.pop(name, None)


def _quote_mode() -> str:
    """``VULTURE_LLM_QUOTE_VERIFY`` — ``off`` / ``observe`` (default) / ``enforce``.

    A mode string rather than a flag, matching ``VULTURE_OBLIGATION_MODE``. Read
    at call time (D14): a mode captured at import cannot be flipped mid-fleet.
    """
    return os.getenv("VULTURE_LLM_QUOTE_VERIFY", "observe").strip().lower() or "observe"


def _reanchor_enabled() -> bool:
    """The LINE actuator: ``enforce`` AND ``VULTURE_LLM_QUOTE_REANCHOR``.

    Requiring ``enforce`` is not the same as being implied by it — reading the
    mode string where the actuator switch was meant is an easy and invisible
    mistake, so both are demanded and both are read at call time.
    """
    return _quote_mode() == "enforce" and env_truthy("VULTURE_LLM_QUOTE_REANCHOR")


def _batch_paths(findings: list[dict], source_path: str) -> list[Path | None]:
    """Resolve each finding's path ONCE — the verifier takes a resolved Path (D17)."""
    return [_resolve_finding_path(f.get("file_path", ""), source_path) for f in findings]


def _resolved_only(paths: list[Path | None]) -> list[Path]:
    """The batch's readable files, DEDUPED: the ``found_elsewhere`` search space.

    ``_batch_paths`` yields one entry per FINDING, so 40 findings spread over 10
    files handed the verifier ~36 siblings of which 9 were distinct — and the
    cross-file scan then paid for every duplicate. `dict.fromkeys` keeps first-seen
    order so the search stays deterministic.
    """
    return list(dict.fromkeys(path for path in paths if path is not None))


def _may_reanchor(outcome: "anchor.AnchorResult") -> bool:
    """Whether this outcome licenses moving a line: the actuator is on, the text
    was located elsewhere, and the move is inside the absolute ceiling."""
    if not _reanchor_enabled():
        return False
    if outcome.status != "reanchored":
        return False
    return _within_delta_ceiling(outcome)


def _within_delta_ceiling(outcome: "anchor.AnchorResult") -> bool:
    """A candidate beyond ``MAX_DELTA`` is a different construct, not a
    mislocation, so it records but never moves the line (§5.3)."""
    if outcome.new_line is None or outcome.delta is None:
        return False
    return abs(outcome.delta) <= anchor.max_delta()


def _apply_reanchor(finding: dict, outcome: "anchor.AnchorResult") -> None:
    """The LINE actuator for a row's OWN citation (§5.3, T4.3). Inert on ship.

    `reanchored` means the quoted text was found, but not where the model said.
    Rewriting `line_start` here — upstream of dedup, of the SSE event and of
    `_attach_code_snippet` — is what makes every later consumer see the VERIFIED
    line, which is the whole point of measuring `anchor_delta`.

    Distinct from `_adopt_line`, which copies a line from a BETTER-ANCHORED
    SIBLING during the dedup merge (AC30). That path only fires when a row has a
    dedup partner; this one corrects a row that stands alone — the common case,
    and the one the mislocated class is made of.

    `claimed_line` is retained by the caller's stamp, so a rewrite is always
    auditable back to what the model actually said.
    """
    if not _may_reanchor(outcome):
        return
    span = max(0, int(finding.get("line_end", 0)) - int(finding.get("line_start", 0)))
    finding["line_start"] = outcome.new_line
    finding["line_end"] = outcome.new_line + span


def _stamp_anchor(finding: dict, path: Path | None, mode: str,
                  siblings: list[Path]) -> None:
    """Record what the verifier observed, as PRIVATE fields. No actuator here.

    ``off`` skips the verifier entirely; the caller still strips, which is the
    property the rollback path depends on.
    """
    if mode == "off":
        return
    outcome = anchor.verify_anchor(finding, path, mode=mode, batch_paths=siblings)
    # Captured BEFORE the actuator runs. `_apply_reanchor` overwrites
    # `line_start`, so reading it afterwards recorded the VERIFIED line as the
    # model's claim: every reanchored row then looked as though the model had
    # been right all along, `claimed_line + delta` pointed at nothing, and the
    # rewrite stopped being auditable — the precise property this stamp exists
    # to preserve, on precisely the mislocated class the feature measures.
    claimed = finding.get("line_start", 0)
    _apply_reanchor(finding, outcome)
    finding.update({
        "_anchor_status": outcome.status,
        "_anchor_reason": outcome.reason,
        "_claimed_line": claimed,
        "_anchor_delta": outcome.delta,
        "_anchor_candidates": outcome.candidates,
        "_anchor_other_path": outcome.other_path,
        "_anchor_quote_chars": outcome.quote_chars,
        "_anchor_quote_tokens": outcome.quote_tokens,
    })


def _restore_dedup_identity(finding: dict) -> None:
    """Put the model's ``check_id`` back as the row's PUBLIC dedup identity.

    AC26's invariant is that stripping the model-authored ``check_id`` changes
    the post-dedup finding count by ZERO, and §5.1 discharges it by preserving
    the value as ``_model_check_id`` with a ``_dedup_key`` fallback. That
    discharge is incomplete in the pipeline: this choke point is UPSTREAM of the
    cross-batch dedup, and ``_strip_private_fields`` deletes ``_model_check_id``
    here — so the private carrier only ever reaches ``_dedup_key`` in a direct
    unit call, never in a real run. Measured: with the private carrier alone,
    ``tests/e2e/test_0057_llm_on_bundle.py``'s LLM duplicate stopped collapsing
    onto its skill twin and the run reported the same defect twice.

    So the identity is restored, not merely remembered. What the strip removes is
    the model's authority over ``code_snippet`` and over the structured schema
    (B3); ``check_id`` remains what it always was — a dedup key that neither
    repository persists (C7), never a catalog id.
    """
    cid = finding.get("_model_check_id")
    if cid and not finding.get("check_id"):
        finding["check_id"] = cid


def _verify_and_strip(findings: list[dict], source_path: str) -> list[dict]:
    """THE choke point (0076 §5.4(1)), immediately after ``_parse_llm_result``.

    Both parse branches converge here, the halved-body size retry re-enters
    through it, and it is upstream of the cross-batch dedup, of the per-finding
    SSE event and of ``_attach_code_snippet`` — so a re-anchored row's line is the
    one every later consumer sees. The strip runs for every finding in every
    configuration; only the stamping is gated.
    """
    mode = _quote_mode()
    if mode == "off":
        # The rollback setting must be free, not merely inert. `_batch_paths`
        # calls `_resolve_finding_path` once per finding (filesystem syscalls),
        # and `_stamp_anchor` would return immediately anyway.
        for finding in findings:
            _restore_dedup_identity(finding)
            _strip_private_fields(finding, _PARSE_PRIVATE_FIELDS)
        return findings
    paths = _batch_paths(findings, source_path)
    siblings = _resolved_only(paths)
    for finding, path in zip(findings, paths, strict=True):
        _stamp_anchor(finding, path, mode, siblings)
        _restore_dedup_identity(finding)
        _strip_private_fields(finding, _PARSE_PRIVATE_FIELDS)
    return findings


def _anchor_rank(finding: dict) -> int:
    """Quality of a row's anchor status; ``-1`` for a row that carries none, so
    an unstamped row neither adopts nor is adopted from."""
    return _ANCHOR_QUALITY.get(str(finding.get("_anchor_status") or ""), -1)


def _adopt_line(survivor: dict, other: dict) -> None:
    """The LINE half of the merge — inert until the actuator is switched on.

    Adopting ``exact`` is pointless if the survivor keeps the line the losing row
    claimed: the whole reason to prefer that row's status is that ITS line was
    the one actually verified.
    """
    if not _reanchor_enabled():
        return
    survivor["line_start"] = other.get("line_start", survivor.get("line_start"))
    survivor["line_end"] = other.get("line_end", survivor.get("line_end"))


def _adopt_anchor(survivor: dict | None, other: dict) -> None:
    """A MAX over the rows collapsing onto one dedup key, never a last-write-wins.

    ``_deduplicate_findings`` keeps the FIRST-SEEN row, and first-seen is
    arbitrary with respect to anchor quality: a batch can raise an ``absent`` row
    at index 0 and an ``exact`` row for the same key at index 3, and the survivor
    would carry ``absent`` — manufacturing a demotion for a finding that WAS
    correctly quoted. This is a field merge among rows that already collapse
    today, so the surviving COUNT is unchanged in every case.

    ``survivor is None`` marks a key that came from ``base`` (the accumulated
    skill findings): those rows are not returned by the dedup and must not be
    stamped with an LLM row's anchor provenance.
    """
    if survivor is None or _anchor_rank(other) <= _anchor_rank(survivor):
        return
    for name in _ADOPTED_ANCHOR_FIELDS:
        survivor[name] = other.get(name)
    _adopt_line(survivor, other)


def _deduplicate_findings(
    base: list[dict], new: list[dict], source_path: str = "",
) -> list[dict]:
    """Return findings from ``new`` not already in ``base``.

    Uses ``check_id`` + normalized ``file_path`` when check_id is present
    (stable, hierarchical). Falls back to normalized title + file_path
    otherwise. Path normalization (P1f) makes the match robust to
    absolute-vs-relative path forms of the same file.

    Args:
        base: Existing findings (e.g. from skill scan).
        new: New findings (e.g. from LLM pass) to filter.
        source_path: Audit source root, used to normalize paths.

    Returns:
        Subset of ``new`` that don't duplicate any entry in ``base``.
    """
    # ``None`` marks a key contributed by ``base``; a real dict is the surviving
    # row for that key, and is the object a later duplicate merges its anchor
    # status into (0076 AC30).
    seen: dict[tuple[str, str], dict | None] = {
        _dedup_key(f, source_path): None for f in base
    }
    unique: list[dict] = []
    for f in new:
        key = _dedup_key(f, source_path)
        if key in seen:
            _adopt_anchor(seen[key], f)
            continue
        seen[key] = f
        unique.append(f)
    return unique


def _collapse_skill_findings(
    findings: list[dict], run_id: str = "",
) -> tuple[list[dict], int]:
    """Collapse ancestor-vs-descendant CWE rows sharing one source line.

    Skills run independently, so a single construct can raise several rows on
    the same ``(file_path, line_start)``. Where one row's CWE is a transitive
    ``ChildOf`` ancestor of another's, the general row carries no remediation
    the specific row doesn't, and is dropped (severity is carried over).
    Sibling CWEs — different weaknesses under a common parent — are left
    alone; each has its own fix.

    The count is always logged so the effect is observable. Failures degrade
    to the uncollapsed list rather than losing findings, and the whole step
    is switched off by ``VULTURE_DISABLE_LINE_COLLAPSE=true``.
    """
    if os.environ.get("VULTURE_DISABLE_LINE_COLLAPSE", "").lower() == "true":
        return findings, 0
    try:
        kept, collapsed = collapse_line_stacks(findings)
    except Exception as exc:  # collapse is an optimisation, never a gate
        logger.warning("line_collapse_failed run_id=%s: %s", run_id, exc)
        return findings, 0
    logger.info(
        "line_collapse run_id=%s before=%d after=%d collapsed=%d",
        run_id, len(findings), len(kept), collapsed,
    )
    return kept, collapsed


def _is_within_root(candidate: Path, root: Path) -> bool:
    """True iff ``candidate`` (already resolved) is inside ``root`` (resolved).

    Uses ``Path.resolve()`` on both so symlink escapes (a finding path that
    points at a symlink inside the tree resolving to ``/etc/...``) are caught.
    Falls back to a string-prefix check on Python versions / paths where
    ``is_relative_to`` is unavailable.
    """
    try:
        return candidate.resolve().is_relative_to(root)
    except AttributeError:  # pragma: no cover — py<3.9
        try:
            candidate.resolve().relative_to(root)
            return True
        except ValueError:
            return False
    except OSError:
        return False


def _resolve_finding_path(file_path: str, source_path: str) -> Path | None:
    """Resolve a finding's file_path to an existing file on disk, CONFINED to
    the audit source root.

    Findings report paths in several forms: absolute, source-root-relative,
    or a bare basename. The LLM-phase ``file_path`` is fully model-controlled
    (parsed raw from model output), so a prompt-injected / hallucinating model
    could emit ``/etc/passwd`` or ``~/.aws/credentials`` and have its content
    read into ``code_snippet`` — which then leaks into the SSE result event.
    To prevent that arbitrary-file-read → exfiltration channel, we reject any
    resolved path that is not under ``source_path`` (symlink-escape safe via
    ``Path.resolve()``).

    When no source root is known (direct unit-test calls), the confinement is
    skipped and the historical absolute/relative resolution applies.
    """
    if not file_path:
        return None
    if not source_path:
        # No root to confine against (e.g. unit tests calling validate with
        # source_path=""). Preserve the historical resolution behaviour.
        p = Path(file_path)
        return p if p.is_file() else None

    root = Path(source_path).resolve()
    p = Path(file_path)
    # Absolute paths are taken verbatim; relative paths are resolved against
    # the source root. Either way the result must be IN-TREE (root-confined).
    candidate = p if p.is_absolute() else (Path(source_path) / file_path)
    if candidate.is_file() and _is_within_root(candidate, root):
        return candidate
    return None


# Feature 0057 P2a: CWEs whose findings embed an actual secret VALUE in the
# offending source line (credential, key, password, cleartext URL). For these,
# the secret must be masked out of ``code_snippet`` before it reaches the SSE
# ``result`` event or the DB column. Non-secret CWEs are left verbatim.
_SECRET_BEARING_CWES: frozenset[str] = frozenset({
    "CWE-798",  # use of hard-coded credentials
    "CWE-319",  # cleartext transmission of sensitive information
    "CWE-312",  # cleartext storage of sensitive information
    "CWE-256",  # plaintext storage of a password
    "CWE-259",  # use of a hard-coded password
    "CWE-321",  # use of a hard-coded cryptographic key (crypto_check embeds key)
    "CWE-522",  # insufficiently protected credentials
})

_REDACTION_PLACEHOLDER = "***REDACTED***"

# A quoted string literal: capture the opening quote so we can re-emit it while
# masking the body. Handles both single- and double-quoted literals.
_QUOTED_LITERAL_RE = re.compile(r"""(['"])(?:\\.|(?!\1)[^\\])*\1""")

# An assignment / key-value right-hand side whose value is NOT a fully quoted
# literal (e.g. ``token = abcd1234``, ``password: hunter2``, ``export KEY=v``,
# or a truncated ``api_key = "AKIA`` whose closing quote was cut). Captures any
# leading indentation plus the variable/key and operator so structure is
# preserved; masks the value. ``^\s*`` lets the branch fire on INDENTED source
# lines; an optional ``export``/``set`` shell prefix is tolerated.
_ASSIGN_RHS_RE = re.compile(
    r"""^(?P<indent>\s*(?:export\s+|set\s+)?)"""
    r"""(?P<lhs>[A-Za-z_][\w.\[\]'"-]*\s*[:=]\s*)"""
    r"""(?P<val>\S.*?)(?P<tail>\s*(?:#.*)?)$"""
)

# A trailing comment body (``# ...`` / ``// ...``). For secret-bearing findings
# a secret can hide in a comment; mask the comment body while keeping the marker.
_COMMENT_BODY_RE = re.compile(r"""(?P<marker>#|//)(?P<body>\s*\S.*)$""")


def _has_unterminated_quote(text: str) -> int:
    """Return the index of a dangling opening quote (a quote char with no
    matching close before end-of-line), or -1 if every quote is balanced.

    Handles the 200-char-truncation leak: when ``extract_snippet`` cuts a long
    secret line, the closing quote (and the secret tail) fall past the cut, so
    the value after the LAST opening quote was never masked by the
    complete-literal pass and would leak its PREFIX.
    """
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            close = text.find(c, i + 1)
            if close == -1:
                return i  # opening quote never closed → dangling
            i = close + 1
        else:
            i += 1
    return -1


def _redact_secret_line(line: str) -> str:
    """Mask secret VALUES in a single source line while preserving structure.

    The numbered-snippet line prefix (``"3: "``) is left untouched by callers;
    this operates on the code portion only. Masks:
      * the BODY of every quoted string VALUE (keeps the quotes; a quoted
        literal in dict-KEY position — immediately followed by ``:`` — is
        preserved so keys survive),
      * an unquoted assignment / key-value RHS (keeps the lhs + operator),
        including INDENTED and ``export``-prefixed lines, and
      * an unterminated opening quote (truncated long-secret lines), and
      * a trailing comment body (a secret hidden in a comment).
    Variable names, keys, quotes and line shape survive so the finding stays
    useful for triage.
    """
    trailing_nl = "\n" if line.endswith("\n") else ""
    body = line.rstrip("\n")

    if _QUOTED_LITERAL_RE.search(body):
        # At least one COMPLETE quoted literal: mask each literal's body, keep
        # quotes. Preserve quoted literals sitting in dict-KEY position (the
        # literal is immediately followed by ``:``) so keys stay readable.
        def _mask(m: re.Match[str]) -> str:
            q = m.group(1)
            after = body[m.end():]
            if after.lstrip().startswith(":"):
                return m.group(0)  # dict key — preserve verbatim
            return f"{q}{_REDACTION_PLACEHOLDER}{q}"

        masked = _QUOTED_LITERAL_RE.sub(_mask, body)
        # After masking complete literals, a dangling opening quote means the
        # closing quote was truncated away — mask its leaked tail to EOL.
        dangling = _has_unterminated_quote(masked)
        if dangling != -1:
            masked = masked[: dangling + 1] + _REDACTION_PLACEHOLDER
        return masked + trailing_nl

    # No complete quoted literal. If there's a lone (truncated) opening quote,
    # mask from it to EOL so the secret prefix is removed.
    dangling = _has_unterminated_quote(body)
    if dangling != -1:
        return body[: dangling + 1] + _REDACTION_PLACEHOLDER + trailing_nl

    # Try to mask an unquoted assignment RHS (indent / export aware).
    m = _ASSIGN_RHS_RE.match(body)
    if m:
        return (
            f"{m.group('indent')}{m.group('lhs')}{_REDACTION_PLACEHOLDER}"
            f"{m.group('tail')}{trailing_nl}"
        )

    # No assignment either — mask a trailing comment body (secret-in-comment).
    cm = _COMMENT_BODY_RE.search(body)
    if cm:
        prefix = body[: cm.start()]
        return f"{prefix}{cm.group('marker')} {_REDACTION_PLACEHOLDER}{trailing_nl}"
    return line


def _redact_snippet(snippet: str) -> str:
    """Redact secret values in a numbered code-window snippet (P2a).

    Each line is of the form ``"<n>: <code>"`` (see ``extract_snippet``). The
    ``"<n>: "`` prefix — carrying the line number and shape — is preserved and
    only the code portion is run through :func:`_redact_secret_line`.
    """
    if not snippet:
        return snippet
    return "\n".join(_redact_numbered_line(raw) for raw in snippet.split("\n"))


def _redact_numbered_line(raw: str) -> str:
    """Redact one presented line, preserving its ``"<n>: "`` prefix exactly.

    The prefix is recovered from :func:`line_format.strip_line_number` (0076
    AC19: ONE reader for the format) rather than from a second hand-rolled
    pattern — the two that existed already disagreed about leading whitespace.
    ``strip_line_number`` is identity on an unprefixed line, so the slice is
    empty there and the line is redacted whole.
    """
    body = line_format.strip_line_number(raw)
    prefix = raw[: len(raw) - len(body)]
    return f"{prefix}{_redact_secret_line(body)}"


def _redact_finding_inplace(finding: dict[str, Any]) -> None:
    """Mask the secret VALUE in a single finding's ``code_snippet`` when the
    finding is secret-bearing (P2a). Idempotent and DRY: this is the single
    redaction primitive invoked from EVERY snippet egress point —

      * the per-finding ``finding`` SSE event (skill + LLM phases), and
      * the ``_attach_code_snippet`` finalisation choke point (SSE ``result``
        + DB row),

    so a secret never reaches the frontend live view, the result snapshot, or
    the persisted ``code_snippet`` column. No-op for non-secret CWEs and for
    findings without a snippet. Re-redacting an already-masked snippet is safe
    (the placeholder carries no secret).
    """
    if str(finding.get("category", "")).strip().upper() not in _SECRET_BEARING_CWES:
        return
    existing = finding.get("code_snippet")
    if existing:
        finding["code_snippet"] = _redact_snippet(existing)


# --- Feature 0057 P6b: provenance vocabulary -----------------------------
# Exactly ONE of these tags is stamped on every finding. The deterministic
# tiers are set centrally at the pre-egress choke point BOTH tiers pass through
# (``_set_provenance``, applied in ``_finalize_finding_inplace`` immediately
# BEFORE each per-finding SSE event, so the live delta and the ``result``
# snapshot agree; ``_attach_code_snippet`` keeps the same call as an idempotent
# backstop for findings that never reach an emit site); the ``llm`` tag is set
# at LLM-finding emission time (run_combined_audit) and PRESERVED here via
# ``setdefault`` semantics; ``llm_l5_verified`` is the L5-survival re-tag set
# at the validate vote choke point (``validate._apply_validation_to_finding``).
#
# The tags are ADDITIVE metadata: they must NOT change the
# ``validate.llm_judge._is_deterministic`` / ``_is_l5_exempt`` determinations,
# which key off ``check_id`` / ``signature_status`` / ``provenance == "llm"``.
PROVENANCE_VALUES: frozenset[str] = frozenset(
    {
        "skill",
        "signature_trusted",
        "signature_candidate",
        "catalog_rollup",
        "llm",
        "llm_l5_verified",
    }
)


def _classify_deterministic_provenance(finding: dict[str, Any]) -> str:
    """Map a DETERMINISTIC-tier finding to its provenance tag.

    Precedence (most specific first):
      * ``signature_status == "trusted"``    → ``signature_trusted``
      * ``signature_status == "candidate"``  → ``signature_candidate``
      * ``check_id`` ending ``.rollup``      → ``catalog_rollup``
        (built by ``catalog_detector._build_rollup_finding`` as
        ``cwe.catalog.cwe_<id>.rollup``)
      * anything else carrying a ``check_id`` → ``skill`` (the dedicated
        skills + keyword catalog hits)
    """
    sig_status = finding.get("signature_status")
    if sig_status == "trusted":
        return "signature_trusted"
    if sig_status == "candidate":
        return "signature_candidate"
    if str(finding.get("check_id", "")).endswith(".rollup"):
        return "catalog_rollup"
    return "skill"


def _set_provenance(finding: dict[str, Any]) -> None:
    """Stamp exactly one ``provenance`` tag on a finding (Feature 0057 P6b).

    ``setdefault`` semantics: a pre-set ``provenance`` (the Phase-1 ``llm`` tag
    on LLM findings) is preserved untouched; only deterministic-tier findings
    that arrive WITHOUT a provenance are classified here. Mutates in place;
    idempotent.
    """
    if finding.get("provenance"):
        return
    finding["provenance"] = _classify_deterministic_provenance(finding)


# Feature 0072 T5.2: per-scope snippet context. Classes whose declared
# refutation scope is wider than a statement (FUNCTION / FILE / WIRING) get a
# LINE-budgeted window — the L5 judge cannot reason about a guard clause or a
# middleware effect from 200 characters. Applied ONLY to those classes to
# bound the token cost (plan §10); policy classes (Scope.NONE — including
# every secret-bearing CWE) and undeclared classes keep the tight legacy
# window the secret-redaction pass was tuned for.
_WIDE_SNIPPET_CONTEXT = 10   # 21 lines; must stay under the judge's
                             # _WINDOW_LINES_MAX render ceiling (T5.4)


def _snippet_params_for(category: str) -> tuple[int, int | None]:
    """(context_lines, max_chars) for extract_snippet, per weakness class.

    Wide only for classes whose declared scope is wider than a statement AND
    reviewed (T2.1a): an unreviewed legacy entry still searches the narrow
    window, so widening its snippet would spend §10's token budget on
    obligations that cannot use it — today that keeps the widening to the
    authorization family.
    """
    from shared.validate.refutation import REFUTATION_MAP, Scope

    ref = REFUTATION_MAP.get(category or "")
    if (ref is not None and ref.scope_reviewed
            and ref.scope in (Scope.FUNCTION, Scope.FILE, Scope.WIRING)):
        return _WIDE_SNIPPET_CONTEXT, None
    return 2, 200


def _attach_code_snippet(
    findings: list[dict[str, Any]],
    source_path: str,
) -> None:
    """Feature 0057 P0.2: populate a real code window on every finding that
    lacks one, read from the referenced source line.

    Central choke point applied to ``all_findings`` (skill + LLM) just before
    the validate stage so the L5 judge always sees a grounded window (R4).
    Mutates findings in place. Additive / no-op for findings that already
    carry a non-empty ``code_snippet`` (several skills set it directly).

    Feature 0057 P6b: ``_set_provenance`` is applied to every finding here too,
    but it is no longer the set-POINT — this call runs after the per-finding SSE
    events, which is how the deltas came to carry no provenance at all. The stamp
    now happens at ``_finalize_finding_inplace`` (immediately before each emit)
    and this pass is the idempotent BACKSTOP for any finding that reaches the
    ``result`` snapshot without passing an emit site.

    A finding whose path cannot be resolved or whose line is missing/zero is
    left with an empty snippet — the L5 selection layer then SKIPS it (P0.3)
    rather than judging blind.
    """
    from shared.tools.file_scanner import read_file_lines

    # P6b backstop. Say plainly what this is now: as of 0078 track C it is a
    # NO-OP on every path that exists. `_finalize_finding_inplace` stamps
    # provenance immediately before both per-finding emits, and rollup parents
    # are tagged `catalog_rollup` by validate/rollup.py where they are built, so
    # nothing reaches here untagged.
    #
    # It is kept because it costs one dict lookup per finding and it is the
    # invariant's last line of defence: if a future path appends findings
    # without going through the emit choke point, this is what stops them
    # reaching the DB provenance-less — the failure mode that made this whole
    # section necessary. It stays decoupled from the best-effort snippet loop
    # below so a read failure there (which the caller catches and logs) cannot
    # skip it. Idempotent; no-op if already set, `llm` included.
    for f in findings:
        _set_provenance(f)

    for f in findings:
        context, max_chars = _snippet_params_for(f.get("category", "") or "")
        wide = max_chars is None
        # T5.2: a wide-scope class gets the line-budget window even when a
        # skill pre-set a narrow one — the window is the judge's evidence,
        # and 200 chars cannot contain a mitigation that lives lines away.
        # Narrow classes keep the legacy behaviour: back-fill only.
        if wide or not f.get("code_snippet"):
            line_start = f.get("line_start", 0) or 0
            try:
                line_start = int(line_start)
            except (TypeError, ValueError):
                line_start = 0
            if line_start >= 1:
                resolved = _resolve_finding_path(f.get("file_path", ""), source_path)
                if resolved is not None:
                    lines = read_file_lines(resolved)
                    if lines:
                        snippet = extract_snippet(
                            lines, line_start,
                            context=context, max_chars=max_chars,
                        )
                        if snippet:
                            f["code_snippet"] = snippet

        # P2a: mask secret VALUES for secret-bearing CWEs, whether the snippet
        # was back-filled above OR pre-set by a skill (e.g. auth_check). This
        # runs at the finalisation choke point so both the SSE result and the
        # DB row carry the redacted form. (The per-finding `finding` SSE events
        # are independently redacted at emission time — see run_combined_audit —
        # so the live frontend view never sees the raw secret either.)
        _redact_finding_inplace(f)


def _assign_finding_id(finding: dict[str, Any], audit_id: str, index: int) -> None:
    """Assign a deterministic finding ID matching the backend's
    `generateFindingID(auditID, title, file_path, index)` hash.

    Mutates `finding` in place. Idempotent: if `finding["id"]` is
    already set, leaves it untouched. Feature 0046 (issue #1).
    """
    if finding.get("id"):
        return
    import hashlib
    raw = f"{audit_id}:{finding.get('title', '')}:{finding.get('file_path', '')}:{index}"
    finding["id"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _finalize_finding_inplace(
    finding: dict[str, Any], run_id: str, index: int,
) -> None:
    """The single pre-egress choke point BOTH tiers pass through.

    Every finding that leaves this process — skill row or LLM row — is emitted
    by ``emitter.finding_event(**_public_view(finding))`` and then carried into
    the ``result`` snapshot, so anything that must be true of an emitted finding
    belongs here rather than in one tier's own loop.

    Category conformance used to live only in the two LLM parse branches. The
    measurement behind it found 30 out-of-vocabulary rows and NINE of them were
    skill rows — every skill row in that run — so covering the LLM path alone
    left a third of the violations on the wire.

    Order is deliberate but not load-bearing for the id: ``_assign_finding_id``
    hashes title + file_path only, so conforming the category first cannot move
    an id. All three steps are idempotent, so a row reaching here twice is
    unchanged the second time.

    Safe to move conformance off the parse branches and onto this later point
    because nothing between them reads ``category``: ``_dedup_key`` keys on
    ``check_id`` or the normalised title plus path, and ``_adopt_anchor`` merges
    only the ``_anchor_*`` stamps.

    ``_set_provenance`` runs FIRST, and runs here rather than only in
    ``_attach_code_snippet``, for the same "two different contents" reason. That
    call site is reached at the "Combine & emit final result" step — after every
    per-finding event has been yielded — so the deterministic tags rode only the
    ``result`` snapshot. That is not merely a live-view cosmetic: the backend
    rescues DELTA findings from any agent that never sent a snapshot, so an agent
    cut off by a context deadline persisted provenance-less rows, and which
    agents those were changed from run to run on the same target. Nothing about
    a finding decided it — only whether its agent got to finish.

    Deferring it bought nothing: provenance is a pure in-memory classification
    with no I/O, which is exactly why it is already a standalone pass there. It
    is first in this function because it reads ``check_id`` /
    ``signature_status`` and must not depend on what the other two steps touch.
    ``setdefault`` semantics preserve the LLM tier's pre-set ``llm`` tag, and the
    later pass in ``_attach_code_snippet`` is now a no-op for everything that
    egressed through here — keep it: it is the backstop for findings that never
    pass an emit site.
    """
    _set_provenance(finding)
    _conform_category(finding)
    _assign_finding_id(finding, run_id, index)
    _redact_finding_inplace(finding)


def _bind_category_enum(
    fn: Callable[..., Generator[str, None, None]],
) -> Callable[..., Generator[str, None, None]]:
    """Bind ``category_enum`` for exactly the wrapped audit's lifetime.

    A decorator rather than an inline ``try``/``finally`` for two reasons. The
    bind needs an honest ``finally``: a generator body cannot be trusted to
    reach its own tail, because a client disconnect closes it mid-stream
    (feature 0061) and an unhandled failure unwinds it — either way the
    vocabulary would otherwise outlive the run and be applied to the NEXT audit
    driven by that context. And doing it here rather than in a hand-written
    wrapper keeps the audit's 12-parameter signature written once.

    ``reset(token)`` rather than ``set(None)`` so an enclosing audit gets its
    own vocabulary back instead of losing it. The set and the reset both run in
    the consumer's context (a generator has no context of its own), which for
    ``_cancellable_stream`` is the one worker context driving the whole run.

    ``category_enum`` is keyword-only here and absent from the wrapped
    function's parameters, so passing it positionally raises rather than being
    silently ignored.
    """
    @functools.wraps(fn)
    def wrapper(
        *args: Any,
        category_enum: frozenset[str] | None = None,
        **kwargs: Any,
    ) -> Generator[str, None, None]:
        token = _CATEGORY_ENUM.set(category_enum)
        reset_conform_stats()
        try:
            yield from fn(*args, **kwargs)
        finally:
            try:
                _CATEGORY_ENUM.reset(token)
            except ValueError:
                # Advanced from a different Context than the one that set it —
                # no caller does this today, but a stale vocabulary silently
                # applied to someone else's findings is worse than a lost reset.
                _CATEGORY_ENUM.set(None)

    return wrapper



# ── feature 0079 B1: model-health preflight ──────────────────────────────────
#
# Six agents (chaos, soc2, ssdf, xss, do178c, asvs) had no preflight. They DO
# degrade gracefully -- reactively, at the guard below that emits "LLM phase
# unavailable" and sets degraded_reason. What they lacked is the ability to skip
# the sweep BEFORE burning the failure budget.
#
# Two measured costs of not having it. With an unreachable endpoint each batch
# is bounded by VULTURE_LLM_CALL_TIMEOUT_SEC and the sweep aborts only after
# VULTURE_LLM_MAX_CONSECUTIVE_FAILURES -- 3 x 120s ~ 6 minutes, replaced by one
# ~3s probe. And that abort is gated on `batch_idx + 1 < len(batches)`, so on a
# tree producing <= 3 batches it never fires at all and the operator gets
# silently wasted calls with no notice.
#
# It lives HERE, not in a per-agent wrapper, for two reasons: one edit reaches
# every agent, and this point is INSIDE the cancel token and the whole-audit
# deadline. A wrapper around run_combined_audit would sit outside both, adding
# an unbounded term to the PROXY >= MAX_AUDIT + LLM_CALL margin rule.


def _preflight_mode() -> str:
    """``off`` / ``observe`` (default) / ``enforce``.

    A mode string, matching VULTURE_OBLIGATION_MODE and VULTURE_LLM_QUOTE_VERIFY.
    An unrecognised value falls back to ``observe``, never to ``enforce``: a typo
    must not start vetoing the LLM tier.
    """
    raw = os.environ.get("VULTURE_LLM_PREFLIGHT", "").strip().lower()
    return raw if raw in ("off", "observe", "enforce") else "observe"


def _probe_llm_reachable() -> tuple[bool, str]:
    """(reachable, reason). Seam for tests; real work is in shared.llm.health."""
    import asyncio

    from shared.llm.health import check_llm_health

    status = asyncio.run(check_llm_health())
    ok = bool(getattr(status, "healthy", False))
    return ok, "" if ok else status.message()


def _preflight_vetoes(effective_use_llm: bool, run_id: str, agent_label: str) -> tuple[bool, str]:
    """Should the LLM sweep be skipped? Returns (veto, notice).

    Fails OPEN in every uncertain case. A probe fault is a defect in the guard,
    not evidence the provider is down, and vetoing on it would let one broken
    probe disable the LLM tier across the fleet.
    """
    if not effective_use_llm:
        return False, ""          # nothing to protect; never pay for a probe
    mode = _preflight_mode()
    if mode == "off":
        return False, ""
    try:
        reachable, reason = _probe_llm_reachable()
    except Exception as exc:  # noqa: BLE001 - fail open, see docstring
        logger.info("llm_preflight run_id=%s agent=%s probe_error=%s", run_id, agent_label, exc)
        return False, ""
    if reachable:
        return False, ""
    logger.info(
        "llm_preflight run_id=%s agent=%s mode=%s unreachable reason=%s",
        run_id, agent_label, mode, reason,
    )
    if mode != "enforce":
        return False, ""          # observe: measured and logged, never acted on
    return True, f"LLM preflight: provider unreachable - {reason}"


@_bind_category_enum
def run_combined_audit(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_map: dict[str, SkillFn],
    domain_label: str = "categories",
    prior_context: str = "",
    skill_tools: list[Any] | None = None,
    instructions: str | None = None,
    model: str | None = None,
    use_llm: bool | None = None,
    validate_use_llm: bool | None = None,
    llm_tier3: bool | None = None,
) -> Generator[str, None, None]:
    """Run skills first (full coverage), then optionally LLM (deeper analysis).

    Always runs pattern-matching skills across all files. When LLM mode
    is enabled and ``skill_tools``/``instructions`` are provided, performs a
    second LLM pass on the subset of files that fits in the context window.
    LLM findings are deduplicated against skill findings so only genuinely
    new issues are added.

    Args:
        run_id: Unique run identifier.
        source_path: Path to source code root.
        categories: Ordered list of skill/category keys to run.
        skill_map: Mapping from category key to skill function.
        domain_label: Label for summary text.
        prior_context: Optional prior findings context from memory bank.
        skill_tools: LLM agent tools (required for LLM pass).
        instructions: LLM agent system prompt (required for LLM pass).
        model: Optional model preference for LLM pass.
        use_llm: Per-request LLM toggle. ``None`` falls back to the
            ``VULTURE_USE_LLM`` env var (module-level ``USE_LLM``).
        category_enum: Keyword-only, consumed by ``_bind_category_enum``. The
            vocabulary this agent advertises through ``/info``; every emitted
            finding is reduced to it at ``_finalize_finding_inplace``. ``None``
            (the default) leaves categories untouched.

    Yields:
        SSE-formatted event strings.
    """
    effective_use_llm = use_llm if use_llm is not None else USE_LLM

    clear_caches()  # Ensure stale file contents don't leak across audit runs
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()
    logger.info("audit_start run_id=%s source=%s categories=%s use_llm=%s",
                run_id, source_path, categories, effective_use_llm)

    # feature 0061: cooperative cancellation. `cancel` is the ambient token the
    # transport flips on client disconnect; `_deadline_val` is the single
    # wall-clock ceiling shared across the skill, generate, and L5 phases so
    # their timeouts cannot stack (F11a). Bound ambiently so the generate
    # (asyncio.run) and L5 (copy_context thread) phases both see it.
    cancel = current_cancel_token()
    _max_audit_s = _safe_int_env("VULTURE_AGENT_MAX_AUDIT_SECONDS", 900)
    _deadline_val: float | None = None
    if _max_audit_s > 0:
        _deadline_val = time.monotonic() + _max_audit_s
        set_audit_deadline(_deadline_val)

    def _cancelled_or_expired() -> bool:
        return (cancel is not None and cancel.cancelled()) or (
            _deadline_val is not None and time.monotonic() > _deadline_val
        )

    # Emit prior findings context if available
    if prior_context:
        yield emitter.text_message(prior_context)

    # --- Phase 1: Skill-based pattern matching (always runs) ---
    scan_code_files(source_path)  # warm file cache

    skill_findings: list[dict] = []
    total = len(categories)
    completed = 0

    _skill_aborted = False  # feature 0061: set on cancel / skill-phase deadline
    pool_workers = min(total, _SKILL_WORKERS)
    # Manual pool management (no `with` / no CM-driven shutdown-with-wait)
    # so that generator GC — which can fire from a worker thread when an
    # SSE consumer disconnects mid-stream — doesn't trigger
    # `RuntimeError: cannot join current thread` via Executor.__exit__.
    pool = ThreadPoolExecutor(max_workers=pool_workers)
    try:
        futures = {}
        for cat in categories:
            fn = skill_map.get(cat)
            if fn is None:
                continue
            futures[pool.submit(retry_skill, fn, source_path)] = cat

        # feature 0061: bound the skill wait by the shared whole-audit deadline
        # and honor cancel, so a hung skill or a client disconnect cannot pin
        # this phase (F2). `as_completed(timeout=)` caps the total wait.
        _skill_timeout = (
            max(0.1, _deadline_val - time.monotonic())
            if _deadline_val is not None else None
        )
        try:
            for future in as_completed(futures, timeout=_skill_timeout):
                if cancel is not None and cancel.cancelled():
                    _skill_aborted = True
                    break
                cat = futures[future]
                yield emitter.text_message(f"Analyzing {cat} patterns...")

                try:
                    result = future.result()
                except Exception as exc:
                    yield emitter.text_message(f"Skill {cat} failed: {str(exc)[:200]}")
                    completed += 1
                    yield emitter.progress_event(
                        files_analyzed=completed,
                        total_files=total,
                        findings_count=len(skill_findings),
                    )
                    continue

                findings = result.get("findings", [])
                # Feature 0046 issue #1: assign deterministic IDs at emission
                # time so L5 streaming `validation_update` events can later
                # reference the same finding via id. The backend's
                # `extractDeltaFindings` only auto-generates IDs when the
                # incoming finding has an empty id field — non-empty IDs are
                # preserved verbatim. Hash matches backend's
                # `generateFindingID(auditID, title, file_path, index)`.
                for finding in findings:
                    # Conform the category, assign the deterministic id, and
                    # (feature 0057 P2a) redact secret-bearing snippets BEFORE
                    # the per-finding SSE event, so the live frontend view — and
                    # any delta-finding DB persistence on a stalled stream —
                    # never sees a raw secret or an out-of-vocabulary category.
                    # Mutates the dict also kept in skill_findings, so the
                    # `_attach_code_snippet` finalisation pass re-sees the
                    # already-masked form (idempotent).
                    _finalize_finding_inplace(
                        finding, run_id, len(skill_findings),
                    )
                    skill_findings.append(finding)
                    yield emitter.finding_event(**_public_view(finding))

                completed += 1
                yield emitter.progress_event(
                    files_analyzed=completed,
                    total_files=total,
                    findings_count=len(skill_findings),
                )
        except TimeoutError:
            _skill_aborted = True
            yield emitter.text_message(
                "[partial results] skill phase wall-clock cap reached; "
                "remaining skills not analyzed."
            )
    finally:
        # feature 0061: on cancel/expiry, cancel pending futures and don't block
        # on in-flight skills. Otherwise wait normally. (If GC'd from a worker
        # thread, wait=True would join that very thread — the RuntimeError
        # fallback drops to wait=False.)
        _drain = _skill_aborted or _cancelled_or_expired()
        try:
            pool.shutdown(wait=not _drain, cancel_futures=_drain)
        except (RuntimeError, TypeError):
            pool.shutdown(wait=False)

    logger.info("skill_phase_done run_id=%s findings=%d", run_id, len(skill_findings))

    # --- Line-stack collapse (skill-vs-skill) -------------------
    # `_deduplicate_findings` below is LLM-vs-skill only; skill rows have never
    # been reconciled against each other. Cross-skill duplication can only be
    # judged once every category has reported, so this runs after the pool
    # drains — the per-finding SSE events already streamed, the collapsed set
    # is what the LLM phase, validation and the final `result` see.
    skill_findings, _collapsed = _collapse_skill_findings(skill_findings, run_id)
    if _collapsed:
        yield emitter.text_message(
            f"Collapsed {_collapsed} generalisation "
            f"{'finding' if _collapsed == 1 else 'findings'} into the more "
            "specific weakness reported on the same line."
        )

    # --- Phase 2: LLM enhancement (optional) ---
    llm_new_findings: list[dict] = []
    actual_input_tokens = 0
    actual_output_tokens = 0
    # Feature 0070 P5 (A.3): a run that WANTED an LLM phase and lost it must not
    # look identical to one that never wanted it. The reason egresses on the
    # `result` event (→ audits.degraded_reason) as well as the thinking stream,
    # which is transient and unqueryable after the fact.
    degraded_reason = ""
    # Feature 0079 B1. Probe BEFORE the sweep, so an unreachable provider costs
    # one ~3s probe rather than VULTURE_LLM_MAX_CONSECUTIVE_FAILURES x
    # VULTURE_LLM_CALL_TIMEOUT_SEC of dead calls -- and gets a legible reason
    # instead of a raw litellm error. Placed after the deadline is armed, so the
    # probe is inside the run's safety envelope.
    #
    # Only reached when the phase would otherwise run: skills-only audits and a
    # cancelled run never pay for it.
    if effective_use_llm and skill_tools and instructions and not _cancelled_or_expired():
        _pf_veto, _pf_notice = _preflight_vetoes(True, run_id, domain_label)
        if _pf_veto:
            effective_use_llm = False
            degraded_reason = _pf_notice
            yield emitter.text_message(_pf_notice + " - returning skill findings only.")

    if effective_use_llm and skill_tools and instructions and not _cancelled_or_expired():
        yield emitter.text_message("Enhancing with LLM analysis...")
        logger.info("llm_phase_start run_id=%s", run_id)
        # §14 P0 rollout gate: record how this run's LLM phase reaches a
        # provider — broker (routed through the key-isolating broker) or env
        # (agent's own key). The §20 rollout removes env keys only once the
        # fleet emits zero llm_path=env.
        from shared.llm.broker import current_llm_path
        logger.info("llm_path run_id=%s path=%s", run_id, current_llm_path())

        # Feature 0057 P1f: the collector now sweeps the whole tree in
        # context-window-sized batches (no single pre-built context / silent
        # tail-drop). It returns a partial-results notice (P1d) when a cap hit.
        #
        # §32.1 #19: the ENTIRE Phase-2 path — including setup (broker provider
        # construction, ModelSettings, Agent build) that lives before the guarded
        # LLM call — is wrapped here so that ANY failure degrades to skills-only.
        # Skill findings were already computed (and, for streaming agents, already
        # emitted); an optional LLM-phase failure must NEVER suppress the final
        # `result`/`agent_end` or throw away a completed skill scan.
        llm_findings: list[dict] = []
        llm_error = None
        llm_notice = None
        try:
            (
                llm_findings, llm_error,
                actual_input_tokens, actual_output_tokens,
                llm_notice,
            ) = _collect_llm_findings(
                run_id=run_id,
                source_path=source_path,
                categories=categories,
                skill_tools=skill_tools,
                instructions=instructions,
                domain_label=domain_label,
                prior_context=prior_context,
                model=model,
                skill_findings=skill_findings,
                llm_tier3=llm_tier3,
            )
        except Exception as exc:  # degradation guard, not a swallow
            logger.warning(
                "llm_phase_failed_degrading run_id=%s error=%s",
                run_id, str(exc)[:200],
            )
            yield emitter.text_message(
                "LLM phase unavailable — returning skill findings only."
            )
            degraded_reason = (
                f"LLM phase unavailable ({type(exc).__name__}: {str(exc)[:180]}) "
                f"— skill findings only"
            )
        if llm_notice:
            yield emitter.text_message(llm_notice)
        if llm_error:
            yield emitter.text_message(llm_error)
            degraded_reason = llm_error
        llm_new_findings = _deduplicate_findings(
            skill_findings, llm_findings, source_path=source_path,
        )

        if llm_new_findings:
            yield emitter.text_message(
                f"LLM discovered {len(llm_new_findings)} additional finding(s)."
            )
            # Continue indexing from the end of skill_findings so IDs
            # remain unique across phases. (Feature 0046 issue #1.)
            base_idx = len(skill_findings)
            for offset, finding in enumerate(llm_new_findings):
                # Feature 0057: tag LLM findings so the validate stage knows
                # they are non-deterministic (L5-demotable), while skill
                # findings stay deterministic/trusted (R2 voter floor).
                finding.setdefault("provenance", "llm")
                # Same choke point as the skill tier above: conform, id, and
                # (feature 0057 P2a) redact secret-bearing LLM-finding snippets
                # before the per-finding SSE event (the LLM is the realistic
                # source of unquoted / env-style / comment-embedded secrets).
                _finalize_finding_inplace(finding, run_id, base_idx + offset)
                yield emitter.finding_event(**_public_view(finding))
        elif not llm_error:
            yield emitter.text_message("LLM analysis complete — no additional findings.")
    else:
        # §14 P0 rollout gate: the LLM phase did not run (skills-only mode or a
        # cancelled/expired run) — no provider key was used at all.
        logger.info("llm_path run_id=%s path=skills", run_id)
    log_conform_stats(run_id, domain_label)

    # --- Combine & emit final result ---
    all_findings = skill_findings + llm_new_findings

    # --- Feature 0057 P0.2: code-grounding -----------------------
    # Populate a real code window on every finding lacking one (read from
    # source) so the L5 judge is never blind (R4). Additive / no-op when a
    # finding already carries a snippet. Skipped if the source is gone.
    try:
        _attach_code_snippet(all_findings, source_path)
    except Exception as exc:  # grounding is best-effort
        logger.warning("code_snippet_attach_failed run_id=%s: %s", run_id, exc)

    # --- Validate stage (feature 0045) ---------------------------
    # Annotates each finding with validation_status + validation_confidence
    # + per-layer check trail. V6: never deletes findings (length-preserving).
    # Disabled via VULTURE_DISABLE_VALIDATE=true env var.
    _validate_enabled = (
        os.environ.get("VULTURE_DISABLE_VALIDATE", "").lower() != "true"
    )
    if _validate_enabled:
        try:
            import queue as _queue
            import threading as _threading

            from shared.validate import ValidateConfig as _ValidateConfig
            from shared.validate import validate as _validate

            # L5 streaming (feature 0046 D6): use a thread-safe queue
            # to bridge from validate's callback-style emit_batch into
            # the generator's yield-based SSE flow.
            _stream_q: "_queue.Queue[list[dict] | None]" = _queue.Queue()

            def _on_validation_update(batch: list[dict]) -> None:
                # Strip non-serialisable / large keys before queuing.
                light = [
                    {
                        "id": f.get("id", ""),
                        "validation_status": f.get("validation_status", ""),
                        "validation_confidence": f.get("validation_confidence", 0.0),
                        "validation": f.get("validation", {}),
                    }
                    for f in batch
                ]
                _stream_q.put(light)

            # Per-request override wins; falls back to env (D4 config surface).
            if validate_use_llm is not None:
                _l5_enabled = bool(validate_use_llm)
            else:
                _l5_enabled = (
                    os.environ.get("VULTURE_USE_VALIDATE_LLM", "").lower() == "true"
                )
            # feature 0061 (F11): skip the L5 *LLM* judge when the audit is
            # already cancelled / past the shared deadline. Deterministic L1/L2
            # still annotate the partial findings cheaply.
            if _cancelled_or_expired():
                _l5_enabled = False
            _vcfg = _ValidateConfig(
                compliance_mode=(
                    os.environ.get("VULTURE_COMPLIANCE_MODE", "").lower() == "true"
                ),
                enable_l1=True,
                enable_l2=True,
                enable_l5=_l5_enabled,
            )

            _v_result_box: list = [None]
            _v_exc_box: list = [None]

            def _run_validate_in_thread() -> None:
                try:
                    _v_result_box[0] = _validate(
                        all_findings, source_path=source_path,
                        audit_id=run_id,
                        config=_vcfg,
                        emit_validation_update=_on_validation_update if _l5_enabled else None,
                    )
                except Exception as e:        # handled by outer try
                    _v_exc_box[0] = e
                finally:
                    _stream_q.put(None)        # sentinel

            # feature 0061 (F11c): a raw threading.Thread does NOT inherit
            # contextvars, so copy the current context (carrying the cancel
            # token + shared whole-audit deadline) into the L5 thread. run_l5
            # reads them to cap its deadline and stop early on cancel.
            _vctx = contextvars.copy_context()
            _vthread = _threading.Thread(
                target=lambda: _vctx.run(_run_validate_in_thread), daemon=True,
            )
            _vthread.start()

            # Drain the queue: emit one validation_update SSE event per
            # batch as L5 produces them. The sentinel `None` means
            # validate finished.
            while True:
                batch = _stream_q.get()
                if batch is None:
                    break
                yield emitter.validation_update_event(batch)
            # feature 0061: bounded join — L5 self-terminates by the shared
            # deadline (it caps its own on `current_audit_deadline`), so never
            # pin the generator/producer indefinitely.
            _join_timeout = (
                max(1.0, _deadline_val - time.monotonic()) + 5.0
                if _deadline_val is not None else None
            )
            _vthread.join(timeout=_join_timeout)
            if _v_exc_box[0] is not None:
                raise _v_exc_box[0]
            v_result = _v_result_box[0]

            for ev_text in v_result.event_texts:
                yield emitter.text_message(ev_text)
            all_findings = v_result.findings
            for parent in v_result.rollups:
                yield emitter.finding_event(**_public_view(parent))
            all_findings = all_findings + v_result.rollups
        except Exception as ve:
            logger.warning("validate stage raised %s; continuing without validation", ve)
            yield emitter.text_message(
                f"[validate] stage failed: {type(ve).__name__}; "
                f"findings emitted without validation_status"
            )
    # --- End validate stage --------------------------------------

    # Split prior_context once and pass to all consumers to avoid redundant splits
    prior_lines = prior_context.split("\n") if prior_context else []

    # Dedup stats against prior context (informational only)
    known_titles = _parse_known_titles(prior_context, prior_lines=prior_lines)
    if known_titles:
        skipped = sum(
            1 for f in all_findings
            if _normalize_title(f.get("title", "")) in known_titles
        )
    else:
        skipped = 0

    if prior_lines:
        used_count = sum(1 for ln in prior_lines if ln.startswith(" ") and ":" in ln)
        dupe_count = _extract_dupe_count(prior_lines)
        yield emitter.dedup_stats_event(
            findings_deduped=skipped,
            prior_findings_used=used_count,
            duplicates_removed=dupe_count,
        )

    # Mechanism 7: Emit token savings whenever prior context exists
    # (even with 0 actual tokens in skill-only mode — the event handles it gracefully)
    if prior_lines:
        savings_event = _emit_token_savings(
            emitter, prior_context,
            findings_total=len(all_findings),
            findings_skipped=skipped,
            actual_input_tokens=actual_input_tokens,
            actual_output_tokens=actual_output_tokens,
            model=model,
            prior_lines=prior_lines,
        )
        if savings_event:
            yield savings_event

    score = compute_score(all_findings, total)
    summary = build_summary(all_findings, categories, domain_label)
    logger.info("audit_done run_id=%s total_findings=%d score=%.1f", run_id, len(all_findings), score)
    result_extra = {"degraded_reason": degraded_reason} if degraded_reason else None
    if degraded_reason:
        logger.warning("audit_degraded run_id=%s reason=%s", run_id, degraded_reason)
    yield emitter.result_event(
        findings=all_findings, summary=summary, score=score, extra=result_extra,
    )
    yield emitter.run_finished()


def _collect_llm_findings(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    source_context: str = "",
    llm_tier3: bool | None = None,
) -> tuple[list[dict], str | None, int, int, str | None]:
    """Run the LLM audit (batch-looped) and collect findings (no SSE wrapping).

    Returns ``(findings, error_message, input_tokens, output_tokens, notice)``.
    ``error_message`` is None on success; ``notice`` carries a partial-results
    message when the sweep stopped early on the budget / work cap (P1d), or
    when Tier-3 was skipped (0059 cost guard). Uses ``asyncio.run`` per issue #19.
    """
    return asyncio.run(
        _collect_llm_findings_batched_async(
            run_id, source_path, categories, skill_tools,
            instructions, domain_label, prior_context, model,
            skill_findings=skill_findings,
            llm_tier3=llm_tier3,
        )
    )


def _resolve_llm_budget_usd() -> float:
    """Parse VULTURE_LLM_BUDGET_USD; <= 0 / unset / invalid ⇒ no USD cap."""
    raw = os.environ.get("VULTURE_LLM_BUDGET_USD", "").strip()
    if not raw:
        return 0.0
    try:
        val = float(raw)
    except (ValueError, TypeError):
        logger.warning("invalid_budget_usd value=%r ignoring", raw)
        return 0.0
    return val if val > 0 else 0.0


def _llm_tier3_enabled(config_value: bool | None = None) -> bool:
    """Feature 0059: should the LLM generate phase analyze Tier-3 files
    (no deterministic findings, not entry/config)?

    Precedence: explicit per-request ``config_value`` > ``VULTURE_LLM_TIER3``
    env (on/true/1/yes) > built-in default **OFF** (the cost guard). OFF scopes
    the LLM sweep to Tier 1 (flagged) + Tier 2 (entry/config); deterministic
    skills/signatures still scan every file regardless.
    """
    if isinstance(config_value, bool):
        return config_value
    return os.environ.get("VULTURE_LLM_TIER3", "").strip().lower() in ("on", "true", "1", "yes")


async def _collect_llm_findings_batched_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    llm_tier3: bool | None = None,
) -> tuple[list[dict], str | None, int, int, str | None]:
    """Feature 0057 P1f + P1d: sweep the WHOLE tree in context-window-sized
    batches instead of a single shot that silently tail-drops files.

    For each batch it runs one agent call (delegating to
    ``_collect_llm_findings_async``), dedups findings across batches, and
    accumulates real token usage. The loop stops when the tree is covered, the
    per-audit file cap (``VULTURE_LLM_MAX_FILES``) is hit, or the estimated USD
    spend crosses ``VULTURE_LLM_BUDGET_USD`` — emitting a partial-results
    notice in the latter two cases.

    Returns ``(findings, error, input_tokens, output_tokens, notice)``.
    """
    max_files = _safe_int_env("VULTURE_LLM_MAX_FILES", 10000)
    budget_usd = _resolve_llm_budget_usd()

    # Feature 0057 P1d: the LLM sweep is bounded by VULTURE_LLM_MAX_FILES, the
    # operative ceiling for the whole-codebase pass. Without passing it here the
    # sweep would silently cap at the smaller global scan limit
    # (VULTURE_MAX_FILES, default 500) and the documented LLM cap could never
    # trip. We take the larger of the two so the LLM phase can sweep beyond the
    # per-skill scan cap up to its own ceiling.
    from shared.tools.file_scanner import MAX_FILES as _SCAN_MAX_FILES
    scan_cap = max(max_files, _SCAN_MAX_FILES)
    # Feature 0059: Tier-3 cost guard (default OFF). When off, the LLM sweep
    # is scoped to flagged + entry/config files; the long tail is skipped (and
    # reported via the notice below). Deterministic skills already scanned all.
    include_tier3 = _llm_tier3_enabled(llm_tier3)
    # Feature 0075: name the extension set explicitly so this sweep and the
    # single-shot path in _build_source_context cannot silently diverge — omitting
    # it walked the DEFAULT WIDE set and fed the model declarative files the other
    # path excludes.
    #
    # Deliberately NOT plain CODE_EXTENSIONS. That set also lacks .sql/.tf/.hcl/
    # .proto, and narrowing to it would drop LLM coverage of a Terraform public
    # bucket or a migration's dynamic SQL — real, findable defects with no evidence
    # against them. Only .graphql/.gql are excluded, and only because they are
    # MEASURED noise: 32 of 108 adjudicated findings were .graphql documents cited
    # at line 1 and 0 of 32 were true positives, including under an adjudicator
    # explicitly told to look for PII-selecting queries and under-privileged
    # mutations. Subtracting the proven-noisy pair beats narrowing to a set whose
    # omissions are untested.
    scanned = _llm_eligible_files(
        scan_code_files(
            source_path, max_files=scan_cap,
            extensions=_llm_feed_extensions(single_shot=False),
        )
    )
    ordered = _prioritize_files(
        scanned, source_path, skill_findings, include_tier3=include_tier3,
    )
    tier3_skipped = (len(scanned) - len(ordered)) if not include_tier3 else 0
    max_chars = _get_max_source_chars(model)
    # Feature 0070 P5 (A.1): keep each batch inside the encoded-body ceiling by
    # BATCHING SMALLER, not by dropping a batch's tail. A char is >= 1 byte, so a
    # char budget below the byte cap keeps the batch under it; files that no
    # longer fit roll into the NEXT batch instead of going unanalyzed, so the
    # ceiling costs latency, never coverage. Multibyte content that still
    # overshoots is caught by the hard backstop in _collect_llm_findings_async.
    _body_cap = _get_max_body_bytes()
    if _body_cap > 0:
        max_chars = min(max_chars, _body_cap)
    # Budget-aware batching: with a USD budget configured the sweep batches
    # cautiously (smaller batches) so cost accrues incrementally and the cap
    # can halt it mid-tree before over-spending; with no budget it packs large
    # batches for efficiency (file count is not the throttle — the context
    # window + budget are; plan §7).
    files_per_batch = (
        _safe_int_env("VULTURE_LLM_FILES_PER_BATCH", 1)
        if budget_usd > 0 else _LLM_FILES_PER_BATCH
    )
    batches = _build_source_batches(
        ordered, source_path, max_chars, skill_findings,
        files_per_batch=files_per_batch,
    )
    # No readable source files → still make ONE tool-enabled call so the LLM
    # can read/list/grep the tree itself (preserves prior single-shot behaviour).
    if not batches:
        batches = [("", [])]

    from shared.llm.provider import estimate_cost

    acc: list[dict] = []
    total_in = 0
    total_out = 0
    files_seen = 0
    notice: str | None = None
    first_error: str | None = None

    # feature 0061: honor cancel + the shared whole-audit deadline BEFORE each
    # call, and bound each call so a hung/slow model cannot starve these checks.
    _cancel = current_cancel_token()
    _deadline = current_audit_deadline()
    # D.1: single retry authority — must run before the first model call.
    _pin_llm_client_retries()
    _consec_cap = _max_consecutive_failures()
    _consec_failures = 0
    _call_timeout = _safe_int_env("VULTURE_LLM_CALL_TIMEOUT_SEC", 120)
    if _call_timeout <= 0:  # 0/negative would make asyncio.wait_for insta-timeout every call
        _call_timeout = 120
    for batch_idx, (batch_text, batch_paths) in enumerate(batches):
        if _cancel is not None and _cancel.cancelled():
            notice = (
                f"[partial results] audit cancelled ({_cancel.reason}); "
                f"stopped after {batch_idx} of {len(batches)} batch(es)."
            )
            logger.warning("audit_cancelled run_id=%s reason=%s batches=%d/%d",
                           run_id, _cancel.reason, batch_idx, len(batches))
            break
        if _deadline is not None and time.monotonic() > _deadline:
            notice = (
                f"[partial results] wall-clock cap reached; "
                f"stopped after {batch_idx} of {len(batches)} batch(es)."
            )
            logger.warning("audit_deadline run_id=%s batches=%d/%d",
                           run_id, batch_idx, len(batches))
            break
        try:
            findings, error, in_tok, out_tok = await asyncio.wait_for(
                _collect_llm_findings_async(
                    run_id, source_path, categories, skill_tools,
                    instructions, domain_label, prior_context, model,
                    skill_findings=skill_findings,
                    source_context=batch_text,
                ),
                timeout=_call_timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            # A hung/slow call is bounded here so the loop regains control to
            # re-check cancel/deadline on the next iteration. The injected
            # CancelledError escapes _collect_llm_findings_async's `except
            # Exception`, so no model cooldown/failure is recorded (F7).
            findings, error, in_tok, out_tok = (
                [], f"llm call timed out after {_call_timeout}s", 0, 0,
            )
        total_in += in_tok
        total_out += out_tok
        files_seen += len(batch_paths)
        if error:
            _consec_failures += 1
            if first_error is None:
                first_error = error
        else:
            # Reset on success so one bad batch does not poison the remainder.
            _consec_failures = 0
        if _consec_cap and _consec_failures >= _consec_cap and batch_idx + 1 < len(batches):
            notice = (
                f"[partial results] LLM phase aborted after {_consec_failures} "
                f"consecutive batch failures; stopped after {batch_idx + 1} of "
                f"{len(batches)} batch(es). Last error: {error}"
            )
            logger.warning(
                "llm_consecutive_failure_abort run_id=%s failures=%d cap=%d "
                "batch=%d/%d last_error=%s",
                run_id, _consec_failures, _consec_cap,
                batch_idx + 1, len(batches), str(error)[:160],
            )
            if first_error is None:
                first_error = notice
            break
        if findings:
            # Dedup across batches AND against skill findings so one vuln seen
            # in two overlapping windows isn't double-reported (P1f).
            new = _deduplicate_findings(
                (skill_findings or []) + acc, findings, source_path=source_path,
            )
            acc.extend(new)

        # --- Caps (P1d): evaluate AFTER the batch so its tokens count ---
        if budget_usd > 0:
            spent = estimate_cost(total_in, total_out, model)
            if spent > budget_usd and batch_idx + 1 < len(batches):
                notice = (
                    f"[partial results] LLM budget cap reached "
                    f"(${spent:.4f} > ${budget_usd:.4f}); stopped after "
                    f"{batch_idx + 1} of {len(batches)} file batch(es). "
                    f"Remaining files were not analyzed by the LLM."
                )
                logger.warning("llm_budget_cap run_id=%s %s", run_id, notice)
                break
        if files_seen >= max_files and batch_idx + 1 < len(batches):
            notice = (
                f"[partial results] LLM file cap reached "
                f"({files_seen} >= VULTURE_LLM_MAX_FILES={max_files}); "
                f"stopped after {batch_idx + 1} of {len(batches)} batch(es)."
            )
            logger.warning("llm_file_cap run_id=%s %s", run_id, notice)
            break

    # Surface a per-call error only when the sweep produced nothing useful.
    err = first_error if (first_error and not acc) else None
    # Feature 0059: never silently reduce scope — report the skipped Tier-3 tail.
    if tier3_skipped > 0:
        tier3_notice = (
            f"[llm-scope] Tier-3 skipped: {tier3_skipped} file(s) (no deterministic "
            f"findings, not entry/config) were NOT sent to the LLM — cost guard. "
            f"Set VULTURE_LLM_TIER3=on or scan --llm-tier3 for full-tree LLM coverage."
        )
        notice = f"{tier3_notice}\n{notice}" if notice else tier3_notice
    return acc, err, total_in, total_out, notice


def _quote_required() -> bool:
    """``VULTURE_LLM_QUOTE_REQUIRED`` — default TRUE, read at call time (D14).

    Its own switch because the added field is 0076's one un-mitigable recall
    risk: a ninth field consumes output tokens and attention, and the model may
    return fewer rows. Flipping it removes the ask from BOTH prompt contracts and
    from the structured schema — a rollback that left it in one of the three
    would keep paying the risk while reporting the feature off.
    """
    return env_flag("VULTURE_LLM_QUOTE_REQUIRED", True)


def _quote_max_lines() -> int:
    """The quote bound the prompt states, read from the verifier's OWN knob.

    ``anchor`` owns ``VULTURE_LLM_QUOTE_MAX_LINES`` and its default; asking it
    keeps the stated bound and the enforced bound the same number. A model told
    "1-3 lines" while the verifier clamps at 2 would be refused for doing exactly
    what it was asked.
    """
    return anchor._knob_int("MAX_LINES")


def _quote_obligation() -> str:
    """THE obligation sentence — one authority, used by both prompt contracts.

    Two properties are load-bearing and are pinned by tests. It names the
    ``"NN: "`` format the model is already looking at, because 0075 made every
    content line carry it and the model WILL echo it (the verifier's normaliser
    strips it; the prompt does not fight it). And the consequence clause is
    "will be reported as unverified", never "do not report findings you cannot
    quote" — the second wording would make the prompt itself a suppression
    mechanism, outside every switch this feature ships and un-rollbackable once
    a run has completed, because the suppressed rows were never emitted (AC20).
    """
    return (
        f"evidence_quote: copy the 1-{_quote_max_lines()} source lines your "
        "finding is about, VERBATIM from the numbered listing above (you may "
        'include the "NN: " prefix). A finding without a quote will be reported '
        "as unverified."
    )


def _field_contract() -> list[str]:
    """The field list every LLM call is shown, plus the evidence obligation.

    One list, so the builder cannot grow a second copy of the contract the way
    the unstructured branch did.
    """
    parts = [
        "For each issue found, provide severity, category, title, description,",
        "file_path, line_start, line_end, and recommendation.",
    ]
    if _quote_required():
        parts.append(_quote_obligation())
    return parts


def _quote_contract_suffix() -> str:
    """The obligation as a suffix for the unstructured instruction block, or ``""``.

    A3: the builder's contract (:func:`_field_contract`) and the unstructured
    branch's instruction block are one policy written twice, in two places that
    are edited independently — which is how a fix applied to one of them silently
    works on one path only. Both therefore append the SAME sentence, from the
    same authority, rather than a paraphrase of it.
    """
    if not _quote_required():
        return ""
    return f"\n{_quote_obligation()}"


def _build_llm_prompt(
    source_path: str,
    categories: list[str],
    domain_label: str,
    source_context: str,
    prior_context: str,
    source_in_system: bool = False,
) -> str:
    """Assemble the LLM audit prompt from source context and prior findings.

    Args:
        source_in_system: If True, source code is embedded in the agent's
            instructions (system message) for Anthropic prompt caching.
            The user prompt then omits the source code to avoid duplication.
    """
    parts = [
        f"Audit the source code at: {source_path}",
        f"Focus on these {domain_label}: {', '.join(categories)}",
        *_field_contract(),
    ]
    # Place prior context before source code so the LLM sees known issues
    # early and primes LLM attention.
    if prior_context:
        parts.append(f"\nContext from prior audits:\n{prior_context}")
    if source_in_system:
        parts.append("\nAnalyze the source code provided in the system instructions.")
    elif source_context:
        parts.append(
            "\nThe source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n"
        )
        parts.append(source_context)
    else:
        parts.append("Use the available tools to analyze the code thoroughly.")
    return "\n".join(parts)


def _extract_token_usage(result: Any, model: str | None = None) -> tuple[int, int]:
    """Extract (input_tokens, output_tokens) from an Agent SDK result.

    Warns when token usage is (0,0) — common with Ollama/local models that
    don't populate the usage fields. This makes silent data loss visible.
    """
    actual_input = 0
    actual_output = 0
    try:
        if hasattr(result, "raw_responses"):
            for resp in result.raw_responses:
                usage = getattr(resp, "usage", None)
                if not usage:
                    continue
                # Use whichever field set is populated (mutually exclusive)
                pt = getattr(usage, "prompt_tokens", 0) or 0
                ct = getattr(usage, "completion_tokens", 0) or 0
                it = getattr(usage, "input_tokens", 0) or 0
                ot = getattr(usage, "output_tokens", 0) or 0
                if pt or ct:
                    actual_input += pt
                    actual_output += ct
                elif it or ot:
                    actual_input += it
                    actual_output += ot
    except Exception:
        logger.debug("token_usage_extraction_failed", exc_info=True)
    if actual_input == 0 and actual_output == 0:
        from shared.llm.provider import is_ollama_model
        model_key = model or os.environ.get("VULTURE_LLM_MODEL", "")
        if is_ollama_model(model_key) or _CUSTOM_BASE_URL:
            logger.warning(
                "token_usage_zero model=%s hint=local_models_may_not_report_usage",
                model_key,
            )
    return actual_input, actual_output


# Check for custom base URL (LM Studio, vLLM, etc.)
_CUSTOM_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")


def _parse_llm_result(result: Any) -> list[dict]:
    """Parse findings from an Agent SDK result, handling structured and raw output."""
    final_output = getattr(result, "final_output", None)
    rows = getattr(final_output, "findings", None)
    if isinstance(rows, list):
        # 0076 B3: the SAME normaliser as the text path. Duck-typed on
        # ``.findings`` rather than on ``AuditOutput`` because the model-visible
        # schema is narrowed per call (§5.2) and is therefore its own class.
        # Category conformance is NOT here: it moved to
        # `_finalize_finding_inplace`, the one choke point the skill tier also
        # passes through (nine of the thirty measured violations were skill rows).
        return [_normalize_finding(row.model_dump()) for row in rows]
    return _parse_llm_findings(str(final_output) if final_output is not None else "")


async def _collect_llm_findings_async(
    run_id: str,
    source_path: str,
    categories: list[str],
    skill_tools: list[Any],
    instructions: str,
    domain_label: str,
    prior_context: str = "",
    model: str | None = None,
    skill_findings: list[dict] | None = None,
    source_context: str = "",
    _size_retry: bool = False,
) -> tuple[list[dict], str | None, int, int]:
    """Async helper: run LLM agent and return (findings, error, input_tokens, output_tokens).

    ``_size_retry`` is set on the internal one-shot retry with a halved source
    budget after a size rejection (feature 0070 P5, A.2) — it stops the retry
    from recursing.
    """
    from agents import Agent, ModelSettings, Runner

    # feature 0064: when VULTURE_LLM_BROKER is on and this run carries a broker
    # token, route THIS run's SDK calls through the internal broker via a
    # per-run model provider carried on the run config. Never a global: with
    # VULTURE_AUDIT_EXECUTOR_WORKERS > 1 a process-global client would bleed
    # one run's broker token into another concurrent run's calls.
    # Dual-mode/fail-safe: None when the broker is off/unconfigured/tokenless,
    # so model selection and today's env-key path are untouched (Mode A).
    from shared.llm.broker import broker_model_provider
    from shared.llm.provider import (
        get_model_settings,
        get_model_with_fallback,
        supports_structured_output,
    )
    from shared.tools.file_lister import make_list_files_tool
    from shared.tools.file_reader import make_read_file_tool
    from shared.tools.pattern_matcher import make_search_pattern_tool
    run_model_provider = broker_model_provider()
    if run_model_provider is not None:
        logger.info("broker_client_per_run run_id=%s", run_id)

    resolved_model = get_model_with_fallback(model)

    if not source_context:
        source_context = _build_source_context(source_path, skill_findings=skill_findings, model=model)
    else:
        # Batched path (P1f): the batch text was packed against a CHAR budget —
        # apply the encoded-byte ceiling here, the single choke point every
        # request passes through (feature 0070 P5, A.1).
        source_context = _enforce_body_byte_cap(source_context, label="batch")
    # Feature 0057 P1c: always attach the read-only file + grep tools, even on
    # the inline-source path. The inline context is a budget-bounded subset of
    # the tree; giving the LLM read/list/grep lets it follow cross-file
    # dataflow into files that didn't fit the window (the batch loop covers
    # breadth; the tools cover depth). The model decides whether to call them.
    #
    # Security: the tools are CONFINED to the audit source root (built per
    # audit) so a prompt-injected / hallucinating model cannot read or grep
    # outside the scanned tree (e.g. /etc/passwd, ~/.aws/credentials) and
    # exfiltrate it via a finding. Falls back to the unconfined module tools
    # only when no source root is known (should not happen in the real pipeline).
    if source_path:
        extra_tools = [
            make_read_file_tool(source_path),
            make_list_files_tool(source_path),
            make_search_pattern_tool(source_path),
        ]
    else:
        from shared.tools.file_lister import list_files_tool
        from shared.tools.file_reader import read_file_tool
        from shared.tools.pattern_matcher import search_pattern_tool
        extra_tools = [read_file_tool, list_files_tool, search_pattern_tool]
    all_tools = list(skill_tools) + extra_tools

    source_in_system = "anthropic" in resolved_model and bool(source_context)
    prompt_text = _build_llm_prompt(
        source_path, categories, domain_label, source_context, prior_context,
        source_in_system=source_in_system,
    )

    # Truncate BEFORE computing max_output so the token budget is based on
    # the final prompt size, not the pre-truncation size.
    budget_warn, precomputed_tokens = _check_context_budget(prompt_text, model)
    if budget_warn:
        logger.warning("context_guard run_id=%s: %s", run_id, budget_warn)
        prompt_text = _truncate_prompt_to_budget(prompt_text, model, estimated_tokens=precomputed_tokens)

    from shared.llm.provider import get_context_window
    env_max_output = _safe_int_env("VULTURE_LLM_MAX_OUTPUT_TOKENS", 16384)
    ctx_window = get_context_window(model)
    prompt_tokens = safe_estimate_tokens(prompt_text)
    # SDK overhead: tool definitions (~150 tokens each) + AuditOutput schema (~600 tokens).
    sdk_overhead = max(512, 150 * len(all_tools) + 600)
    max_output = min(env_max_output, max(2048, ctx_window - prompt_tokens - sdk_overhead))
    model_settings_dict = get_model_settings(model)
    # D.1: the retry pin rides in `extra_args` and is only deliverable on the
    # SDK's LiteLLM path. A per-run broker provider replaces model resolution
    # with an OpenAI client, so drop it there (the broker's own client already
    # sets max_retries=0).
    model_settings_dict = _drop_litellm_only_settings(
        model_settings_dict, broker_active=run_model_provider is not None,
    )
    model_settings_dict["max_tokens"] = max_output

    # For Anthropic models, embed source code in the system message (instructions)
    # so it benefits from prompt caching across repeated audits of the same codebase.
    # LiteLLM auto-injects cache_control breakpoints on system messages when the
    # anthropic-beta header is present (see get_model_settings).
    if "anthropic" in resolved_model and source_context:
        augmented_instructions = (
            f"{instructions}\n\n"
            "The source code files are provided below. Analyze them carefully "
            "for security and compliance issues.\n\n"
            f"{source_context}"
        )
    else:
        augmented_instructions = instructions

    # Name the declared vocabulary to the model when the agent has one.
    augmented_instructions = (augmented_instructions or "") + \
        _category_vocabulary_suffix(current_category_enum())

    # Custom OpenAI-compatible endpoints (vLLM, LM Studio, etc.) and Gemini may
    # not support structured output (response_format with JSON schema) alongside
    # the function-calling tools we always attach.  Skip output_type in those
    # cases and rely on prompt-based JSON + _parse_llm_findings fallback.
    use_structured = supports_structured_output(resolved_model)
    if not use_structured:
        augmented_instructions += (
            "\n\nIMPORTANT: Return findings as a JSON array. Each object must have: "
            "severity, category, title, description, file_path, line_start, line_end, recommendation. "
            "Wrap the array in ```json ... ``` fences."
        ) + _quote_contract_suffix()

    agent_kwargs: dict[str, Any] = {
        "name": "auditor",
        "instructions": augmented_instructions,
        "tools": all_tools,
        "model": resolved_model,
        "model_settings": ModelSettings(**model_settings_dict),
    }
    if use_structured:
        agent_kwargs["output_type"] = _model_visible_output(_quote_required())

    agent = Agent(**agent_kwargs)

    from shared.llm.errors import LLMErrorKind, classify_llm_error, retry_llm_call
    from shared.llm.loop_guard import LoopDetectedError, create_loop_guard_hooks

    # Feature 0070 P5 (defect C): ``hooks`` is a ``Runner.run()`` parameter, not
    # a RunConfig field — on any SDK version. The old code passed it to
    # RunConfig, so the TypeError fired on EVERY run and the guard was dropped.
    global _LOOP_GUARD_WARNED
    hooks, _detector = create_loop_guard_hooks()
    if hooks is None:
        if not _LOOP_GUARD_WARNED:
            _LOOP_GUARD_WARNED = True  # once per process, not once per run
            logger.warning(
                "loop_guard_unavailable: SDK RunHooks missing; tool loops are "
                "NOT bounded. Set VULTURE_REQUIRE_LOOP_GUARD=true to fail",
            )
        if _require_loop_guard():
            logger.error("loop_guard_required_unavailable run_id=%s", run_id)
            return [], (
                "LLM analysis refused: tool loop guard unavailable and "
                "VULTURE_REQUIRE_LOOP_GUARD=true"
            ), 0, 0

    async def _run_agent():
        kwargs: dict[str, Any] = {}
        if hooks is not None:
            kwargs["hooks"] = hooks
        if run_model_provider is not None:
            try:
                from agents import RunConfig  # type: ignore[import-untyped]
            except ImportError as exc:
                # §26/M11: broker required but RunConfig missing → FAIL CLOSED
                # (never fall back to the env-key global client, which would leak
                # the keys the broker isolates); raise → skills-only (N2).
                raise RuntimeError("broker required but agents.RunConfig unavailable") from exc
            kwargs["run_config"] = RunConfig(model_provider=run_model_provider)  # type: ignore[call-arg]
        # D.3: bound the SDK's agent loop. Without it one attempt can issue an
        # unbounded number of model calls (~16 measured), invisible to
        # retry_llm_call's budget and uncounted by the tool-loop guard.
        kwargs["max_turns"] = _max_turns()
        return await Runner.run(agent, input=prompt_text, **kwargs)

    from shared.llm.broker import aclose_broker_client
    from shared.llm.cooldown import cooldown_manager

    try:
        result = await retry_llm_call(_run_agent, max_attempts=3)
        actual_input, actual_output = _extract_token_usage(result, model=model)
        findings = _verify_and_strip(_parse_llm_result(result), source_path)
        cooldown_manager.record_success(resolved_model)
    except LoopDetectedError as exc:
        # Loop is an agent reasoning failure, not a model failure — don't cool down the model.
        logger.info("loop_detected run_id=%s: %s (not recording model cooldown)", run_id, exc)
        return [], f"LLM agent aborted: {exc}", 0, 0
    except Exception as exc:
        kind = classify_llm_error(exc)
        # Feature 0070 P5 (A.2): a size rejection is NOT transient — retrying the
        # identical request fails identically, which is why CONTEXT_OVERFLOW is
        # (correctly) absent from RETRYABLE_KINDS. But a *smaller* request is a
        # different request: halve the source body and try exactly once more,
        # then degrade. No model cooldown for the first attempt — the model is
        # healthy, our request was too big.
        halved = (
            _halve_source_context(source_context)
            if kind == LLMErrorKind.CONTEXT_OVERFLOW and not _size_retry
            else ""
        )
        if halved:
            logger.warning(
                "llm_size_retry run_id=%s kind=%s bytes=%d->%d error=%s",
                run_id, kind.value, len(source_context.encode("utf-8")),
                len(halved.encode("utf-8")), str(exc)[:200],
            )
            return await _collect_llm_findings_async(
                run_id, source_path, categories, skill_tools,
                instructions, domain_label, prior_context, model,
                skill_findings=skill_findings,
                source_context=halved,
                _size_retry=True,
            )
        cooldown_manager.record_failure(resolved_model, error_kind=kind.value)
        logger.warning("llm_failed kind=%s error=%s", kind.value, str(exc)[:200])
        return [], f"LLM analysis failed ({kind.value}): {str(exc)[:200]}", 0, 0
    finally:
        # §26/M7: close this run's broker client so its httpx pool/FDs don't
        # leak in the long-lived agent process (no-op when the broker was off).
        await aclose_broker_client()

    return findings, None, actual_input, actual_output


def compute_score(findings: list[dict], total_items: int) -> float:
    """Compute compliance score based on findings.

    Uses a logarithmic decay curve so scores degrade gradually:
    - 0 findings = 100%
    - A few low/medium findings = 70-90%
    - Multiple high findings = 40-60%
    - Many critical findings = 10-30%
    """
    if not findings:
        return 100.0
    penalty = sum(_SEVERITY_WEIGHTS.get(normalize_severity(f.get("severity", "info")), 0.0) for f in findings)
    scale = max(30.0, total_items * 10.0)
    return round(max(5.0, 100.0 / (1.0 + penalty / scale)), 1)


def build_summary(findings: list[dict], categories: list[str], domain_label: str) -> str:
    """Build a human-readable summary."""
    count = len(categories)
    if not findings:
        return f"No issues found across {count} {domain_label}."
    return f"Found {len(findings)} issue(s) across {count} {domain_label}."



def _parse_llm_findings(output: str) -> list[dict]:
    """Extract structured findings from LLM text output.

    Attempt order (feature 0076 §5.1), each falling through only on failure so a
    compliant model's output is unaffected byte for byte: fenced block ->
    ``_scan_json_arrays`` (or the pre-0076 bare regex when
    ``VULTURE_LLM_JSON_SCAN=false``) -> ``_salvage_truncated_array`` -> ``[]``.
    """
    # Category conformance moved to `_finalize_finding_inplace` (see
    # `_parse_llm_result`) so the skill tier is covered by the same call.
    return [_normalize_finding(row) for row in _extract_finding_rows(output)]


def _extract_finding_rows(output: str) -> list[dict]:
    """The first attempt that produces a row list wins; ``[]`` when none does."""
    for attempt in (_fenced_json_rows, _scanned_json_rows, _salvage_truncated_array):
        rows = attempt(output)
        if rows is not None:
            return rows
    return []


def _loads_list(text: str | None) -> list | None:
    """``json.loads`` restricted to arrays; ``None`` on absent or invalid input."""
    if text is None:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, list) else None


def _only_dicts(value: list) -> list[dict]:
    """Every dict entry of a decoded array — RECALL, not ranking: a sloppy row
    such as ``{"title": "b"}`` is too key-poor to make an array look like a
    payload and is still a finding."""
    return [row for row in value if isinstance(row, dict)]


def _dict_rows(value: list | None) -> list[dict] | None:
    """:func:`_only_dicts`, tolerant of the "nothing decoded" signal."""
    if value is None:
        return None
    return _only_dicts(value)


def _fenced_json_rows(output: str) -> list[dict] | None:
    """The ```` ```json ... ``` ```` block — tried FIRST and unchanged (0076 T1.2)."""
    match = _LLM_JSON_FENCED_RE.search(output)
    if match is None:
        return None
    return _dict_rows(_loads_list(match.group(1)))


def _scanned_json_rows(output: str) -> list[dict] | None:
    """The brace-safe scan, or the pre-0076 regex under the rollback switch."""
    if _json_scan_enabled():
        return _scan_json_arrays(output)
    match = _LLM_JSON_BARE_RE.search(output)
    return _dict_rows(_loads_list(match.group(1) if match else None))


def _json_scan_enabled() -> bool:
    """``VULTURE_LLM_JSON_SCAN`` — default TRUE, read at call time (D14)."""
    return env_flag("VULTURE_LLM_JSON_SCAN", True)


def _json_salvage_enabled() -> bool:
    """``VULTURE_LLM_JSON_SALVAGE`` — default TRUE, read at call time (D14)."""
    return env_flag("VULTURE_LLM_JSON_SALVAGE", True)


def _try_decode(output: str, index: int) -> Any:
    """``raw_decode`` at *index*, or ``None`` when nothing valid starts there."""
    try:
        value, _end = json.JSONDecoder().raw_decode(output, index)
    except ValueError:
        return None
    return value


def _score_array(value: list) -> tuple[int, int, int] | None:
    """Rank a decoded array as a findings payload, or ``None`` if it is not one.

    KEY EVIDENCE DOMINATES ROW COUNT, and the ordering is load-bearing. Scored
    ``(len(rows), hits)`` instead, tuple comparison puts row count first and the
    three-row decoy ``[{"id":1},{"id":2},{"id":3}]`` — an everyday TS example in
    model prose, scoring ``(3, 3)`` — outranks the real one-row payload
    ``(1, 9)``, losing the whole batch in a new shape. Returning ``None`` for a
    zero-hit array is the other half: a decoy that carries no finding key is not
    a candidate at all, whatever the ordering downstream turns out to be.
    """
    hits = [_key_hits(row) for row in value]
    if not any(hits):
        return None
    return (_strong_rows(hits), sum(hits), len(_only_dicts(value)))


def _key_hits(row: Any) -> int:
    """Finding-shaped keys carried by one decoded entry; ``0`` for a non-dict."""
    if not isinstance(row, dict):
        return 0
    return len(_FINDING_KEYS & set(row))


def _strong_rows(hits: list[int]) -> int:
    """Rows carrying at least two finding keys — the DOMINANT evidence term."""
    return sum(1 for count in hits if count >= 2)


def _decoded_arrays(output: str) -> Generator[list, None, None]:
    """Every JSON array that decodes from a ``[`` in *output*, in order.

    Exact where the regex was heuristic. Scanning EVERY ``[`` rather than
    returning the first that decodes is a recall requirement: a model that opens
    with prose containing ``["a","b"]``, or whose quote holds ``[{ id: 1 }]``,
    would otherwise have its real payload shadowed by the decoy.
    """
    for index, char in enumerate(output):
        if char != "[":
            continue
        value = _try_decode(output, index)
        if isinstance(value, list):
            yield value


def _better_candidate(
    best: tuple[tuple[int, int, int], list[dict]] | None, value: list,
) -> tuple[tuple[int, int, int], list[dict]] | None:
    """Keep the higher-scoring array; ties take the LATER one, because a model
    that restates its answer puts the corrected payload at the end."""
    score = _score_array(value)
    if score is None:
        return best
    if best is not None and score < best[0]:
        return best
    return (score, _only_dicts(value))


def _scan_json_arrays(output: str) -> list[dict] | None:
    """Find the BEST JSON array of findings in *output*, brace-safely.

    ``None`` — not ``[]`` — is the "nothing here" signal, so the caller can fall
    through to salvage instead of treating a decoy-only response as an answer.
    """
    best: tuple[tuple[int, int, int], list[dict]] | None = None
    for value in _decoded_arrays(output):
        best = _better_candidate(best, value)
    return None if best is None else best[1]


def _unclosed_array_start(output: str) -> int | None:
    """Index of the FIRST ``[`` that does not decode — the truncated array.

    It must be the first, not the last. A truncated payload's opening bracket
    fails to decode because nothing closes it, but so does every ``[`` inside a
    string value after it — and 0076 makes those the common case, because
    ``evidence_quote`` is VERBATIM SOURCE and `m[key]`, `x[i]`, `map[string]int`
    are everyday code. Taking the last match started the salvage in the middle
    of a string literal, recovered nothing, and lost the whole truncated batch:
    the exact recall failure salvage exists to prevent.
    """
    for index, char in enumerate(output):
        if char == "[" and _try_decode(output, index) is None:
            return index
    return None


def _whole_objects_from(output: str, start: int) -> list[dict]:
    """Decode successive whole objects after ``output[start] == '['``.

    Stops at the first fragment, which is the partial tail the output-token cap
    cut off. Linear: ``raw_decode`` returns the index it stopped at, so each
    character is consumed once.
    """
    rows: list[dict] = []
    index = start + 1
    decoder = json.JSONDecoder()
    while index < len(output):
        index = _skip_separators(output, index)
        try:
            value, index = decoder.raw_decode(output, index)
        except ValueError:
            return rows
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _skip_separators(output: str, index: int) -> int:
    """Advance past commas and whitespace between two array elements."""
    while index < len(output) and output[index] in ", \t\r\n":
        index += 1
    return index


def _salvage_truncated_array(output: str) -> list[dict] | None:
    """Recover rows from an array the model never closed.

    A response cut at ``VULTURE_LLM_MAX_OUTPUT_TOKENS`` ends mid-array; without
    this the whole batch is lost because neither pattern can match text with no
    ``]``. Gated by ``VULTURE_LLM_JSON_SALVAGE`` (default true) and never silent:
    the recovered row count is logged as ``llm_json_salvaged``.
    """
    if not _json_salvage_enabled():
        return None
    start = _unclosed_array_start(output)
    if start is None:
        return None
    rows = _whole_objects_from(output, start)
    if not rows:
        return None
    logger.warning("llm_json_salvaged rows=%d", len(rows))
    return rows


def _coerce_path(value: Any) -> str:
    """A model-authored ``file_path`` reaches the resolver, the dedup key and Go
    as a string. The line fields are coerced (B2); this one was copied verbatim,
    so a model returning a list or a number propagated a non-str all the way to
    ``_resolve_finding_path``. Junk costs the PATH, never the FINDING."""
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _coerce_line(value: Any, default: int = 0) -> int:
    """B2: a model that returns ``"55"`` must not be silently dropped by Go's
    ``LineStart int`` unmarshal (``agui/finding_parse.go:33``). Junk costs the
    LINE, never the FINDING — the caller's default is returned instead."""
    if isinstance(value, bool):
        return default
    try:
        if isinstance(value, int | float):
            return int(value)
        return int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        # NaN and +/-Infinity reach here: `json.loads` accepts all three by
        # default, so a model emitting `"line_start": NaN` produced a float that
        # `int()` refuses — ValueError for NaN, OverflowError for Infinity —
        # and the exception escaped the parser and lost the entire batch. The
        # docstring's promise (junk costs the LINE, never the FINDING) was not
        # kept for exactly the inputs a malformed model response supplies.
        return default


def _coerce_lines_enabled() -> bool:
    """``VULTURE_LLM_COERCE_LINES`` — default TRUE, read at call time (D14)."""
    return env_flag("VULTURE_LLM_COERCE_LINES", True)


def _normalize_lines(raw: dict) -> dict[str, Any]:
    """B4: both fields leave the parser as ints, ``>= 0`` and ordered.

    A negative index silently addresses the END of a Python list, so a negative
    line would read the wrong code rather than fail; an inverted range is a
    nonsense window for every downstream reader.
    """
    if not _coerce_lines_enabled():
        return {"line_start": raw.get("line_start", 0), "line_end": raw.get("line_end", 0)}
    start = max(_coerce_line(raw.get("line_start")), 0)
    return {"line_start": start, "line_end": max(_coerce_line(raw.get("line_end")), start)}


def _non_empty(name: str, value: Any) -> dict[str, Any]:
    """``{name: value}`` when *value* is truthy, otherwise no key at all."""
    return {name: value} if value else {}


def _carry_check_id(raw: dict) -> dict[str, Any]:
    """The model's ``check_id``: trusted verbatim, or PRESERVED privately.

    Stripping it outright re-keys the row onto ``(normalised_title, path)``
    (``_dedup_key`` prefers ``check_id``), so a skill row already carrying that
    title in that file deletes the LLM row. AC26 pins the count invariant: the
    value survives as ``_model_check_id`` and ``_dedup_key`` falls back to it.
    """
    name = _MODEL_FORBIDDEN_CHECK_ID[0]
    cid = raw.get(name) or ""
    if not cid:
        return {}
    if env_truthy(_TRUST_MODEL_CHECK_ID):
        return {name: cid}
    return {"_model_check_id": cid}


def _carry_evidence(raw: dict) -> dict[str, Any]:
    """The evidence fields: the quote always, the two forbidden ones by switch.

    ``code_snippet`` is a SOURCE-READ artefact produced by
    ``_attach_code_snippet``; a model-authored string is indistinguishable from
    one, displaces the real window fed to L5, and scores +3 in the Go winner
    selection. It is admitted only under ``VULTURE_LLM_TRUST_MODEL_SNIPPET``.
    """
    name = _MODEL_FORBIDDEN_SNIPPET[0]
    # Only when the model actually quoted: an always-present empty string would
    # add a key to every finding a non-complying model returns, which changes the
    # normaliser's output shape for callers that never asked for the feature.
    carried: dict[str, Any] = _non_empty("evidence_quote", raw.get("evidence_quote"))
    snippet = raw.get(name) or ""
    if snippet and env_truthy(_TRUST_MODEL_SNIPPET):
        carried[name] = snippet
    carried.update(_carry_check_id(raw))
    return carried


# The agent's DECLARED category vocabulary, when it opts in by passing
# `category_enum` to run_combined_audit. Findings are reduced to it before
# egress, because every consumer -- frontend category filters, cross-agent
# dedup, the OWASP categorizer -- keys off the enum the agent advertises
# through /info.
#
# Measured: 30 of the SSDF agent's 56 rows carried a category outside its own
# declared ["PO","PS","PW","RV"], the LLM tier alone inventing 15 distinct
# strings (`PW-102`, `PW-1/PW-3`, `PW2`, practice-group NAMES). Default None
# leaves behaviour unchanged for every agent that does not opt in.
#
# A ContextVar and NOT a module global. `transport/sse_app.py` drives up to
# VULTURE_AUDIT_EXECUTOR_WORKERS (default 8) audit generators at once in one
# interpreter, each inside its own `contextvars.copy_context()`, so a global
# here is shared mutable state between unrelated audits: whichever generator
# started second silently reduced the FIRST one's categories against its own
# enum -- an SSDF run conforming against SOC2's vocabulary, or the reverse,
# decided by nothing but start order.
#
# This is the third time ambient per-run state has been bitten by exactly that.
# The other two are documented in place and reached the same conclusion: the
# broker's per-run model provider (`_build_llm_agent` below, and
# `llm/broker.py:broker_model_provider`) replaced a `set_default_openai_client`
# process global that "would bleed one run's broker token into another
# concurrent run's calls". So the vocabulary is bound the way the cancel token
# and the broker token already are -- per context, set and reset around one run.
_CATEGORY_ENUM: contextvars.ContextVar[frozenset[str] | None] = contextvars.ContextVar(
    "vulture_category_enum", default=None,
)


def current_category_enum() -> frozenset[str] | None:
    """The vocabulary declared by the audit running in THIS context (or None).

    Mirrors ``current_cancel_token`` / ``current_llm_path``: ambient per-run
    state is read through a function so no caller can capture it at import.
    """
    return _CATEGORY_ENUM.get()


def _category_vocabulary_suffix(allowed: frozenset[str] | None) -> str:
    """Prompt text naming the agent's DECLARED category vocabulary.

    Track B conformed categories after the fact, and the normaliser never
    guesses — right for `PW-3.3` -> `PW`, useless for prose. Measured with the
    LLM tier running to completion, soc2 produced nine categories, six of them
    prose labels (`Access Logging`, `Change Management`, ...) with no declared
    prefix to reduce, so they passed through untouched.

    Prevention at the source; the normaliser stays as the net. Neither alone
    suffices: a prompt cannot bind a model, and the normaliser cannot rescue a
    label with nothing to reduce.

    Sorted, so two identical audits build an identical prompt — an unstable
    system message would defeat prompt caching for no benefit.
    """
    if not allowed:
        return ""
    values = ", ".join(sorted(allowed))
    return (
        "\n\nCATEGORY VOCABULARY: the `category` field must be EXACTLY one of: "
        f"{values}. Use the identifier only — not a descriptive name, not a "
        "phrase, and not two joined with a slash. Put any extra specificity in "
        "`title` or `description` instead."
    )


# AC3.5: a category rewrite must be COUNTED, never silent. The plan gates the
# whole normalisation on "report, per agent, the count before and after, and the
# rows that collided" — and the rewrite is precisely what CREATES collisions,
# because the Go merge makes category the primary dedup discriminant. A collapse
# can therefore delete a row, and without this it was unobservable.
#
# A ContextVar, for the same reason the vocabulary itself is one: up to
# VULTURE_AUDIT_EXECUTOR_WORKERS audits share the interpreter, and a module
# counter would blend them.
_CONFORM_STATS: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "vulture_conform_stats", default=None
)


def reset_conform_stats() -> None:
    """Start a fresh tally for this audit."""
    _CONFORM_STATS.set({"rewritten": 0, "unreducible": 0, "pairs": {}})


def conform_stats() -> dict[str, Any]:
    """The tally for this audit; zeroes when nothing has been recorded."""
    cur = _CONFORM_STATS.get()
    return cur if cur is not None else {"rewritten": 0, "unreducible": 0, "pairs": {}}


def _record_conform(raw: str, fixed: str) -> None:
    """Tally one decision. ``raw == fixed`` means nothing was rewritten."""
    cur = _CONFORM_STATS.get()
    if cur is None:
        cur = {"rewritten": 0, "unreducible": 0, "pairs": {}}
        _CONFORM_STATS.set(cur)
    if raw == fixed:
        # Unchanged AND not declared: the normaliser refuses to guess, so this
        # is the number that says the prompt-side fix is not landing.
        allowed = current_category_enum()
        if allowed and raw not in allowed:
            cur["unreducible"] += 1
        return
    cur["rewritten"] += 1
    cur["pairs"][(raw, fixed)] = cur["pairs"].get((raw, fixed), 0) + 1


def log_conform_stats(run_id: str, agent_label: str) -> None:
    """Emit the per-audit summary. Silent when nothing was rewritten."""
    st = conform_stats()
    if not st["rewritten"] and not st["unreducible"]:
        return
    mapping = ", ".join(
        f"{src}->{dst}x{n}" for (src, dst), n in sorted(st["pairs"].items())
    )
    logger.info(
        "category_conform run_id=%s agent=%s rewritten=%d unreducible=%d %s",
        run_id, agent_label, st["rewritten"], st["unreducible"], mapping,
    )


def _conform_category(finding: dict) -> dict:
    """Reduce ``category`` to the declared enum, preserving the detail."""
    allowed = current_category_enum()
    if not allowed:
        return finding
    raw = finding.get("category")
    if not isinstance(raw, str):
        return finding
    fixed = normalize_to_enum(raw, allowed)
    _record_conform(raw, fixed)
    if fixed == raw:
        return finding
    finding["category"] = fixed
    # Keep the specific id the agent actually said, and keep it somewhere that
    # SURVIVES. The first cut put it in a `practice` key, which `model.Finding`
    # has no field for, so the agui unmarshal DISCARDED it at the Go boundary --
    # it never reached the DB, the SSE consumer or the frontend, which made
    # "nothing is lost" false end to end. `description` is an existing field on
    # both models, so appending there actually preserves it.
    #
    # `practice` is still set for in-process consumers (the validation layers
    # run agent-side and can read it), but it is no longer the only copy.
    finding.setdefault("practice", raw)
    desc = finding.get("description")
    if isinstance(desc, str) and raw not in desc:
        finding["description"] = f"{desc.rstrip()} (reported as: {raw})"
    return finding


def _normalize_finding(raw: dict) -> dict:
    """Normalize a finding dict to expected schema.

    BOTH parse branches route through here (0076 §5.1): the structured branch
    used to call ``model_dump()`` directly, which is how ``code_snippet`` and
    ``check_id`` leaked from the model on that path only.
    """
    normalized: dict[str, Any] = {
        "severity": normalize_severity(raw.get("severity", "info")),
        "category": raw.get("category", "unknown"),
        "title": raw.get("title", "Untitled finding"),
        "description": raw.get("description", ""),
        "file_path": _coerce_path(raw.get("file_path", "")),
        "recommendation": raw.get("recommendation", ""),
    }
    normalized.update(_normalize_lines(raw))
    normalized.update(_carry_evidence(raw))
    return normalized
