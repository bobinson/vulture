"""Model capability profiles — feature 0089 §2.

The prompt a model can actually follow depends on a handful of capabilities,
not on its name. Encoding them as a profile means one canonical prompt source
plus a renderer, rather than eight per-model prompt variants that drift.

Built OVER ``shared/llm/provider.py``: that module stays the single model
table. Nothing here re-derives a context window or re-parses a model string
that ``provider`` already resolves.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)


class Structured(str, Enum):
    """How (or whether) the endpoint can enforce a JSON shape itself."""

    NATIVE = "native"                # response_format json_schema
    EMULATED_TOOL = "emulated_tool"  # LiteLLM fakes it with a forced tool call
    NONE = "none"                    # prompt-only contract


class ToolSchema(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    NONE = "none"


@dataclass(frozen=True)
class ModelProfile:
    """What a prompt must adapt to. Fields are LLD §2, exactly."""

    family: str
    system_role: bool
    structured: Structured
    tool_schema: ToolSchema
    json_mode_with_tools: bool
    reasoning_leak: bool
    reasoning_overhead_tokens: int
    fence_habit: bool
    prefers_xml_sections: bool
    output_language_pin: bool
    ctx_window: int
    ctx_provenance: str


# Per-FAMILY capabilities. Deliberately not per-model: a new model of a known
# family needs no row. Context window is NOT here — provider.CONTEXT_WINDOWS
# owns it and is consulted at resolve time.
#
# `structured` for anthropic is EMULATED_TOOL, not NATIVE: LiteLLM emulates
# json_schema by injecting a synthetic tool and forcing tool_choice, which
# makes the real read/list/grep tools uncallable. `supports_structured_output`
# returned True for it because the check was `"gemini" not in model` — the
# gemini reasoning was documented but never generalised.
MODEL_PROFILES: dict[str, dict] = {
    "openai":    dict(system_role=True,  structured=Structured.NATIVE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=False, reasoning_overhead_tokens=0,
                      fence_habit=False, prefers_xml_sections=False,
                      output_language_pin=False),
    "o-series":  dict(system_role=True,  structured=Structured.NATIVE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=True,  reasoning_overhead_tokens=700,
                      fence_habit=False, prefers_xml_sections=False,
                      output_language_pin=False),
    "claude":    dict(system_role=True,  structured=Structured.EMULATED_TOOL,
                      tool_schema=ToolSchema.ANTHROPIC, json_mode_with_tools=False,
                      reasoning_leak=False, reasoning_overhead_tokens=0,
                      fence_habit=True,  prefers_xml_sections=True,
                      output_language_pin=False),
    "gemini":    dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.GEMINI, json_mode_with_tools=False,
                      reasoning_leak=False, reasoning_overhead_tokens=0,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=False),
    "qwen":      dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=True,  reasoning_overhead_tokens=700,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=True),
    # gemma's chat template has NO system role: a system message is folded into
    # the first user turn or dropped outright. Everything load-bearing must
    # survive relocation.
    "gemma":     dict(system_role=False, structured=Structured.NONE,
                      tool_schema=ToolSchema.NONE, json_mode_with_tools=False,
                      reasoning_leak=False, reasoning_overhead_tokens=0,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=False),
    "glm":       dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=True,  reasoning_overhead_tokens=400,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=True),
    "kimi":      dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=True,  reasoning_overhead_tokens=400,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=True),
    "seed":      dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=False, reasoning_overhead_tokens=0,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=True),
    # The fallback. Assumes the least capability that is still usable, so an
    # unknown model gets the prompt-only contract rather than a silent failure.
    "generic":   dict(system_role=True,  structured=Structured.NONE,
                      tool_schema=ToolSchema.OPENAI, json_mode_with_tools=True,
                      reasoning_leak=True,  reasoning_overhead_tokens=400,
                      fence_habit=True,  prefers_xml_sections=False,
                      output_language_pin=False),
}

# Substring → family. Ordered: the first match wins, so more specific patterns
# come first ("gpt-oss" is a local OSS model, not OpenAI hosted).
_FAMILY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("gpt-oss", "generic"),
    ("qwen", "qwen"),
    ("gemma", "gemma"),
    ("claude", "claude"),
    ("anthropic", "claude"),
    ("gemini", "gemini"),
    ("glm", "glm"),
    ("kimi", "kimi"),
    ("moonshot", "kimi"),
    ("seed", "seed"),
    ("doubao", "seed"),
    ("o1", "o-series"),
    ("o3", "o-series"),
    ("o4", "o-series"),
    ("gpt", "openai"),
)


def family_for(model: str) -> str:
    """The capability family of a resolved model string."""
    low = (model or "").lower()
    for needle, family in _FAMILY_PATTERNS:
        if needle in low:
            return family
    return "generic"


@functools.lru_cache(maxsize=64)
def profile_for(model: str | None = None) -> ModelProfile:
    """Resolve a model string to its capability profile.

    Cached: the model string is constant for the life of an audit, and
    ``render`` is called once per batch.
    """
    from shared.llm.provider import get_model, resolve_context_window

    resolved = get_model(model)
    family = family_for(resolved)
    if family == "generic":
        log.info("[prompt] no capability profile for %r; using generic", resolved)
    caps = MODEL_PROFILES[family]
    window, provenance = resolve_context_window(resolved)
    return ModelProfile(family=family, ctx_window=window,
                        ctx_provenance=provenance, **caps)
