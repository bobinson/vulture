"""LLM helper for prove agent — robust JSON extraction from LLM responses.

Includes token tracking, cooldown/fallback, context-window-aware prompt
truncation, and proper model string resolution for direct litellm calls.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field

from shared.llm.cooldown import cooldown_manager
from shared.llm.provider import (
    estimate_cost,
    get_context_window,
    resolve_model_for_litellm_with_fallback,
)
from shared.prompt import Mode, PromptSpec, RenderedPrompt, profile_for, render
from shared.prompt.extract import _balanced_object, _fenced_lines, extract_object
from shared.prompt.manifests.prove_system import PROVE_RETRY, PROVE_SYSTEM
from shared.prompt.render import _fill

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

# ── Prompt bytes come from the shared prompt library (feature 0089 Phase 2.2) ─
# The JSON-only system message and the retry guidance were spelled out inline
# here. They are now rendered from the fragments under
# `shared/prompt/fragments/prove/`, which transcribe them byte for byte; the
# parity net is `agents/shared/tests/unit/prompt/test_0089_parity_prove_wire.py`
# and `..._parity_prove_system.py`.
#
# Rendered once at import against the resolved model profile. Item 4.5 flips the
# render below to ADAPT: on the default openai profile that is byte-identical to
# the transcription (the profile reaches only `output_budget_hint` and
# `response_format`, and this call site uses neither), so the shipped default
# moves no byte. ADAPT earns its keep on a profile whose chat template has no
# system role (gemma), where it relocates the JSON-API system turn into the
# user turn rather than emitting a system message the template would drop.
_PROMPT_PROFILE = profile_for(None)


def _render(spec) -> RenderedPrompt:
    """ADAPT-render one prove spec for the resolved model profile (Item 4.5).

    ADAPT, not TRANSCRIBE: on the default openai profile it is byte-identical
    to the transcription (the profile reaches only `response_format`, which
    this JSON call site discards), so the flip moves no byte for the shipped
    default. It earns its keep on a profile whose chat template has no system
    role (gemma), where ADAPT folds the JSON-API system turn into the front of
    the single user turn instead of emitting a system message that would be
    dropped."""
    return render(spec, _PROMPT_PROFILE, mode=Mode.ADAPT)


def render_prove_prompt(user_fragment: str, domain: dict[str, str], **runtime) -> str:
    """The USER turn for one plan / reflect / analyze call (feature 0089 Phase 2.6).

    `user_fragment` is the collapsed template id (`"prove/plan"`, `"prove/reflect"`
    or `"prove/analyze"`); `domain` is the per-strategy / per-protocol slot table
    (`persona`, `domain_rules`, …); `runtime` are the per-call fills (`title`,
    `category`, …). They merge into one variables dict and resolve in a single
    ADAPT pass (Item 4.5), so this reproduces byte for byte what
    `_{PLAN,REFLECT,ANALYZE}_PROMPT.format(**runtime)` produced before the flip —
    the five/five/three inline copies are gone from the runtime, replaced by one
    template each.

    The spec is built here, not imported from a manifest, on purpose: this
    family keeps its per-strategy `prove/plan_{name}` specs as the golden/lint
    oracle (they carry cwe's `filename` orphan and the family's goldens), and a
    parallel collapsed manifest would only duplicate their backlog annotations
    under a new id. The template's bytes are pinned instead by
    `test_0089_parity_prove_collapse.py`. Only `user_fragments` is set; the
    JSON-API system turn is prepended separately by `_system_turn()` inside
    `llm_json_call`, unchanged by this flip.

    Why the domain values are resolved against `runtime` FIRST: `render._fill`
    substitutes in ONE pass and never rescans a value (feature 0089's
    value-is-not-template guarantee), so a `{code_snippet}` sitting INSIDE the
    cwe/owasp `evidence_block` slot value would survive verbatim if it were only
    handed to the skeleton fill. The live `_PLAN_PROMPT.format(...)` filled those
    positions, so reproducing its bytes means resolving them too. Doing it here,
    on the DOMAIN table (authored library constants), is safe in a way a second
    pass over the whole prompt would not be: it cannot turn an
    attacker-controlled runtime value into a template, because runtime values are
    never rescanned — only the trusted domain templates are, and only once.
    """
    resolved_domain = {k: _fill(v, runtime) for k, v in domain.items()}
    spec = PromptSpec(
        id=f"prove_runtime_{user_fragment.rsplit('/', 1)[-1]}",
        tier="prove",
        fragments=(),
        user_fragments=(user_fragment,),
        variables={**resolved_domain, **runtime},
    )
    return _render(spec).user


# The system turn as the LIBRARY places it, role included. Phase 1 found that a
# hardcoded role here is exactly how every prove prompt could end up in the
# wrong turn, so the placement is the library's to state, not this module's.
_SYSTEM_TURN: tuple[dict, ...] = tuple(_render(PROVE_SYSTEM).messages)


def _compose_turns(user_content: str) -> list[dict]:
    """The wire turns, with no two consecutive user messages.

    `_system_turn()` renders whatever role the library says the JSON-API message
    belongs in. Under ADAPT with a profile that has NO system role (rule 2), that
    message comes back as a USER turn — and concatenating it in front of the real
    user turn produced `['user', 'user']` on the wire. Gemma's template, the very
    family that motivates rule 2, is alternation-strict, so the flip broke exactly
    the case it was made for. Baseline before the flip: `['system', 'user']`.

    So a user-role system turn is FOLDED into the front of the user content
    rather than emitted as its own message. A real system turn is passed
    through untouched.
    """
    turns = _system_turn()
    lead = [t for t in turns if t.get("role") == "user"]
    rest = [t for t in turns if t.get("role") != "user"]
    if lead:
        prefix = "\n\n".join(t["content"] for t in lead if t.get("content"))
        user_content = f"{prefix}\n\n{user_content}" if prefix else user_content
    return [*rest, {"role": "user", "content": user_content}]


def _system_turn() -> list[dict]:
    """A fresh copy of the rendered system turn, for one request.

    Copied per call because the messages list is handed to litellm, which is
    free to rewrite it for a provider; the shared render must not be edited in
    place. A function rather than an inline comprehension so `llm_json_call`'s
    branch count is unchanged by this flip.
    """
    return [dict(turn) for turn in _SYSTEM_TURN]


# The system text alone: `_truncate_prompt` budgets for it.
_SYSTEM_MSG = _render(PROVE_SYSTEM).instructions

# Retry guidance, indexed by attempt. `PROVE_RETRY` has no entry for attempt 0
# because live sends no guidance then, and the empty string at index 0 is that
# absence rather than prompt text — a property of this call site, which is why
# the library declines to represent it.
_RETRY_GUIDANCE = [
    _render(PROVE_RETRY[n]).user if n in PROVE_RETRY else ""
    for n in range(max(PROVE_RETRY) + 1)
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
            # `prompt + guidance` is concatenation, not a join: each guidance
            # variant carries its own leading blank line (see the fragments'
            # `verbatim: true`), so a joiner here would emit four newlines
            # where the live payload has two.
            messages = _compose_turns(prompt + guidance)
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

    Delegates to the shared library's object path. That chain IS this
    function's, moved to `shared/prompt/extract.py` in feature 0089 §11.3 —
    same four strategies in the same order (direct parse, thinking-preamble
    skip, markdown fences, brace-counted balanced object) — plus the `<think>`
    reasoning strip the findings-array path already had, which stops a
    reasoning model's abandoned draft being returned instead of its answer.

    `extract_object` returns `None` for "no object anywhere" where this returns
    `{}`, so the warning below fires only on a genuine parse failure and a model
    that really answered `{}` is no longer logged as one.
    """
    found = extract_object(text)
    if found is None:
        logger.warning("Could not extract JSON from LLM response: %.200s", text)
        return {}
    return found


# Both parsers below now live in the shared library, whose docstrings record
# them as moved from this module (`_balanced_object` <- `_find_balanced_json`,
# `_fenced_lines` <- `_strip_markdown_fences`). Kept here as delegations rather
# than as second copies, so the tree holds exactly one implementation of each
# and the version under test is the version that runs.
def _find_balanced_json(text: str) -> dict | None:
    """The first balanced `{...}` in *text*, brace-counted; `None` if there is none."""
    return _balanced_object(text)


def _strip_markdown_fences(text: str) -> str:
    """The content between markdown fence markers; *text* when none was captured."""
    return _fenced_lines(text)
