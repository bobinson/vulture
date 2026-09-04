"""render() — the one place role placement happens. Feature 0089 §4.

Two modes. TRANSCRIBE concatenates fragment text into the roles their `role:`
declares and does NOTHING else; it exists so the migration can reproduce
today's prompts byte for byte, because every adaptive rule below changes
bytes. ADAPT applies the rules. The mode is a call-site constant, not a flag.

Each rule is one function of RenderState -> RenderState, cyclomatic <= 5, and
they compose as a pipeline (LLD §11.1). A rule that does not apply returns its
input unchanged; no rule contains a profile if-ladder.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from . import registry
from .fragment import Fragment, Role, Stance
from .profile import ModelProfile, Structured
from .slots import new_nonce, wrap


class Mode(str, Enum):
    TRANSCRIBE = "TRANSCRIBE"
    ADAPT = "ADAPT"


@dataclass(frozen=True)
class RenderState:
    system: tuple[str, ...]
    user: tuple[str, ...]
    tools: tuple[str, ...]
    profile: ModelProfile
    response_format: dict | None = None
    nonce: str = ""


@dataclass(frozen=True)
class RenderedPrompt:
    instructions: str
    user: str
    messages: list[dict]
    tool_specs: list[dict] | None
    response_format: dict | None
    output_budget_hint: int
    fingerprint: str
    fragments: tuple[str, ...]

    @property
    def system(self) -> str:            # readability alias
        return self.instructions


def _texts(ids: tuple[str, ...]) -> list[Fragment]:
    return [registry.get(i) for i in ids]


def _fill(text: str, variables: dict) -> str:
    if not variables:
        return text
    out = text
    for k, v in variables.items():
        out = out.replace("{" + k + "}", str(v))
    return out


# ── ADAPT rules — one function each, <= 5 branches, order matters ──────────

def _rule_language(st: RenderState, frags: list[Fragment]) -> list[Fragment]:
    """Rule 9: admit the language pin only where the profile needs it."""
    if st.profile.output_language_pin:
        return frags
    return [f for f in frags if Stance.BINDS_LANGUAGE not in f.stance]


def _rule_json_contract(st: RenderState, frags: list[Fragment]) -> list[Fragment]:
    """Rule 4+5: the prose JSON contract only when the API cannot enforce it."""
    if st.profile.structured is Structured.NONE:
        return frags
    return [f for f in frags if Stance.REQUIRES_FENCE not in f.stance]


def _response_format(profile: ModelProfile, has_tools: bool) -> dict | None:
    """Rule 3+4: never response_format alongside tools the model must call."""
    if profile.structured is Structured.NONE:
        return None
    if has_tools and not profile.json_mode_with_tools:
        return None
    return {"type": "json_object"}


def _budget(profile: ModelProfile, prompt_chars: int) -> int:
    """Rule 8: reasoning overhead is a number, never a sentence in a prompt."""
    approx_prompt_tokens = prompt_chars // 4
    headroom = profile.ctx_window - approx_prompt_tokens
    return max(512, headroom - profile.reasoning_overhead_tokens)


def render(spec, profile: ModelProfile, *, mode: Mode = Mode.TRANSCRIBE) -> RenderedPrompt:
    """Compose `spec` for `profile`. Pure: no env reads, no I/O."""
    sys_frags = _texts(spec.fragments)
    usr_frags = _texts(spec.user_fragments)
    nonce = new_nonce() if spec.slots else ""

    if mode is Mode.ADAPT:
        st = RenderState(system=(), user=(), tools=spec.tools, profile=profile)
        sys_frags = _rule_language(st, _rule_json_contract(st, sys_frags))
        mirrored = [f for f in sys_frags if f.role is Role.SYSTEM_USER_MIRROR]
        if not profile.system_role:
            usr_frags = sys_frags + usr_frags
            sys_frags = []
        elif mirrored:
            usr_frags = mirrored + usr_frags

    sys_text = "\n\n".join(_fill(f.text, spec.variables) for f in sys_frags)
    usr_parts = [_fill(f.text, spec.variables) for f in usr_frags]
    usr_parts += [wrap(s, nonce) for s in spec.slots]
    usr_text = "\n\n".join(p for p in usr_parts if p)

    messages: list[dict] = []
    if sys_text:
        messages.append({"role": "system", "content": sys_text})
    if usr_text:
        messages.append({"role": "user", "content": usr_text})

    rf = _response_format(profile, bool(spec.tools)) if mode is Mode.ADAPT else None
    body = sys_text + usr_text
    fp = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    return RenderedPrompt(
        instructions=sys_text, user=usr_text, messages=messages,
        tool_specs=None, response_format=rf,
        output_budget_hint=_budget(profile, len(body)),
        fingerprint=fp,
        fragments=tuple(spec.fragments) + tuple(spec.user_fragments),
    )
