"""LLM helper for prove agent — robust JSON extraction from LLM responses.

Includes token tracking, cooldown/fallback, context-window-aware prompt
truncation, and proper model string resolution for direct litellm calls.
"""

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field

from shared.llm.cooldown import cooldown_manager
from shared.llm.provider import (
    estimate_cost,
    get_context_window,
    resolve_model_for_litellm_with_fallback,
)

# Cache resolved model string to avoid cooldown/fallback logic on every call
_cached_model: str | None = None
_cached_model_ts: float = 0.0
_CACHE_TTL = 60.0  # seconds


def _get_cached_model(preference: str | None = None) -> str:
    """Return resolved model string, cached for 60s."""
    global _cached_model, _cached_model_ts
    now = time.monotonic()
    if _cached_model is not None and (now - _cached_model_ts) < _CACHE_TTL:
        return _cached_model
    _cached_model = resolve_model_for_litellm_with_fallback(preference)
    _cached_model_ts = now
    return _cached_model

logger = logging.getLogger(__name__)

# Thinking preamble patterns (text-based, not XML tags)
_THINKING_PREAMBLE_RE = re.compile(
    r"^.*?(?:Thinking Process|Analysis|Reasoning|Thought|Step[- ]by[- ]Step|Let me)"
    r".*?(?=\{)",
    re.DOTALL,
)

_MAX_RETRIES = 3
_TEMPERATURES = [0.1, 0.4, 0.8]
# Cap output tokens — must be large enough for verbose models that
# emit "Thinking Process:" preambles before the JSON payload.
def _safe_int_env(name: str, default: int) -> int:
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


_DEFAULT_MAX_TOKENS = _safe_int_env("VULTURE_PROVE_MAX_OUTPUT_TOKENS", 4096)

# System message to enforce JSON-only output (effective across model families)
_SYSTEM_MSG = (
    "You are a JSON API. Reply with ONLY a single JSON object. "
    "No thinking process, no analysis, no markdown, no explanation. "
    "Just the JSON object."
)

# Retry guidance appended on retries to steer the model toward valid JSON
_RETRY_GUIDANCE = [
    "",  # no guidance on first attempt
    "\n\nIMPORTANT: Your previous response was not valid JSON. Reply with ONLY a JSON object — no markdown, no explanation, no Thinking Process, no analysis preamble.",
    "\n\nCRITICAL: Previous attempts failed JSON parsing. Output EXACTLY one JSON object: {\"key\": \"value\"}. Nothing else. No text before or after the JSON.",
]

# Rough chars-per-token multiplier (same as shared.tools.memory_client)
_CHARS_PER_TOKEN = 4


@dataclass
class ProveTokenUsage:
    """Accumulates token usage across all LLM calls in a prove session.

    Thread-safe via a lock since background discovery may trigger LLM calls.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    call_count: int = 0
    errors: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, input_t: int, output_t: int) -> None:
        """Record token usage from a single LLM call."""
        with self._lock:
            self.input_tokens += input_t
            self.output_tokens += output_t
            self.call_count += 1

    def record_error(self) -> None:
        """Record a failed LLM call."""
        with self._lock:
            self.errors += 1

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def estimate_cost_usd(self, model: str | None = None) -> float:
        """Estimate cost using the provider cost table."""
        return estimate_cost(self.input_tokens, self.output_tokens, model)


# Module-level session accumulator — reset per prove session via reset_token_usage().
_session_usage = ProveTokenUsage()


def get_token_usage() -> ProveTokenUsage:
    """Get the current session's accumulated token usage."""
    return _session_usage


def reset_token_usage() -> None:
    """Reset token usage for a new prove session."""
    global _session_usage
    _session_usage = ProveTokenUsage()


def _truncate_prompt(prompt: str, max_tokens: int) -> str:
    """Truncate prompt to fit within context window minus output budget.

    Uses a conservative chars-per-token estimate. Leaves room for the
    system message (~50 tokens) and output tokens.
    """
    ctx_window = get_context_window()
    # Reserve: system message (~50 tokens) + output budget + 256 safety margin
    available = ctx_window - max_tokens - 50 - 256
    if available <= 0:
        available = 1024  # absolute minimum
    max_chars = available * _CHARS_PER_TOKEN
    if len(prompt) > max_chars:
        logger.info(
            "prompt_truncated chars=%d max_chars=%d ctx_window=%d",
            len(prompt), max_chars, ctx_window,
        )
        return prompt[:max_chars] + "\n...[truncated to fit context window]"
    return prompt


async def llm_json_call(
    prompt: str,
    *,
    required_fields: list[str] | None = None,
    max_tokens: int = _DEFAULT_MAX_TOKENS,
    model_preference: str | None = None,
) -> dict:
    """Call LLM and extract JSON from response, with retry on empty/invalid results.

    Uses cooldown-aware model resolution and tracks token usage per session.

    Args:
        prompt: The prompt to send to the LLM.
        required_fields: If specified, retry when these fields are missing or empty
                         in the returned dict.
        max_tokens: Maximum output tokens to generate (prevents verbose waste).
        model_preference: Optional model override (key or full name).
    """
    from litellm import acompletion

    # Resolve model with cooldown/fallback (cached for 60s)
    model = _get_cached_model(model_preference)

    # Truncate prompt to fit context window
    prompt = _truncate_prompt(prompt, max_tokens)

    # For custom OpenAI-compatible endpoints (LM Studio, vLLM, Ollama),
    # litellm needs api_key + api_base passed explicitly when using
    # provider-prefixed models like "openai/gpt-oss-20b".
    base_kwargs: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }
    custom_base = os.environ.get("OPENAI_BASE_URL", "")
    if custom_base:
        base_kwargs["api_base"] = custom_base
        if not os.environ.get("OPENAI_API_KEY"):
            base_kwargs["api_key"] = "not-needed"

    for attempt in range(_MAX_RETRIES):
        try:
            # Append retry guidance on subsequent attempts
            guidance = _RETRY_GUIDANCE[min(attempt, len(_RETRY_GUIDANCE) - 1)]
            messages = [
                {"role": "system", "content": _SYSTEM_MSG},
                {"role": "user", "content": prompt + guidance},
            ]
            kwargs = {**base_kwargs, "messages": messages, "temperature": _TEMPERATURES[attempt]}
            response = await acompletion(**kwargs)
            text = response.choices[0].message.content or ""

            # Track token usage from response
            _record_usage(response, model)

            result = _extract_json(text)

            # Validate required fields
            if result and required_fields:
                missing = [f for f in required_fields if not result.get(f)]
                if missing and attempt < _MAX_RETRIES - 1:
                    logger.info(
                        "LLM response missing fields %s (attempt %d), retrying",
                        missing, attempt + 1,
                    )
                    continue

            if result:
                cooldown_manager.record_success(model)
                return result

            if attempt < _MAX_RETRIES - 1:
                logger.info(
                    "LLM returned empty JSON (attempt %d), retrying with guidance",
                    attempt + 1,
                )
        except Exception as exc:
            logger.warning("LLM call failed (attempt %d): %s", attempt + 1, exc)
            _session_usage.record_error()
            if attempt == _MAX_RETRIES - 1:
                cooldown_manager.record_failure(model)
                return {}
    return {}


def _record_usage(response: object, model: str) -> None:
    """Extract and accumulate token usage from a litellm response."""
    try:
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        input_t = getattr(usage, "prompt_tokens", 0) or 0
        output_t = getattr(usage, "completion_tokens", 0) or 0
        if input_t > 0 or output_t > 0:
            _session_usage.record(input_t, output_t)
            logger.debug(
                "prove_llm_usage model=%s input=%d output=%d cumulative=%d",
                model, input_t, output_t, _session_usage.total_tokens,
            )
    except Exception:
        logger.debug("token_usage_extraction_failed", exc_info=True)


def _extract_json(text: str) -> dict:
    """Extract a JSON object from LLM text.

    Handles: <think> XML tags, text-based thinking preambles,
    markdown code fences, and arbitrarily nested JSON objects.
    """
    # Strip <think>...</think> blocks (qwen/deepseek)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Strip <output>...</output> wrapper (some models)
    text = re.sub(r"</?output>", "", text)
    text = text.strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strip text-based thinking preambles ("Thinking Process:", "Analysis:", etc.)
    if _THINKING_PREAMBLE_RE.match(text):
        text = text[text.index("{"):]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Strip markdown code fences — extract fenced content
    if "```" in text:
        text = _strip_markdown_fences(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Find first balanced JSON object via brace counting
    extracted = _find_balanced_json(text)
    if extracted:
        return extracted

    logger.warning("Could not extract JSON from LLM response: %.200s", text)
    return {}


def _strip_markdown_fences(text: str) -> str:
    """Extract content from within markdown code fences."""
    lines = text.split("\n")
    filtered = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            filtered.append(line)
    # If we captured fenced content, use it; otherwise return original
    if filtered:
        return "\n".join(filtered).strip()
    return text


def _find_balanced_json(text: str) -> dict | None:
    """Find the first balanced JSON object using brace counting.

    Handles arbitrary nesting depth unlike a simple regex.
    Skips braces inside quoted strings.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    # This brace pair wasn't valid JSON, try next opening brace
                    next_start = text.find("{", start + 1)
                    if next_start != -1 and next_start < i:
                        return _find_balanced_json(text[next_start:])
                    return None
    return None
