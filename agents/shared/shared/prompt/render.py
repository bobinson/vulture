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
import re
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


# A `{name}` placeholder: lowercase identifier, matching `Fragment.variables()`.
_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def _fill(text: str, variables: dict) -> str:
    """Substitute `{name}` placeholders in ONE pass.

    Not `str.format`, because a prompt may contain literal braces — a JSON
    exemplar does — and `.format` would raise on them or demand they be doubled,
    which is how a fragment ends up recording the ENCODING of a prompt instead
    of the prompt (feature 0089 defects #6/#7).

    But not sequential `str.replace` either, which is what this was. That
    rescans text it has already substituted, so a VALUE containing a later
    key's placeholder gets expanded too:

        variables = {"a": "x{b}y", "b": "B"}
        replace-loop -> "xBy"      # the value steered the template
        one pass     -> "x{b}y"    # the value is data

    That difference is reachable with attacker-controlled input. Discovery does
    `site.technologies.append(f"Server: {server}")` from the scanned target's
    raw `Server` header (`shared/discovery/helpers.py`), so a target answering
    `Server: {framework_hints}` could splice another variable's contents into
    its own line — 10 of 20 ordered pairs of the discover prompt's five
    variables diverged, every one a forward reference. It does not widen egress
    (both sides are the same target's own bytes) but a value must never be able
    to act as template, and the pre-flip `.format` call did not allow it.

    An unknown placeholder is left verbatim rather than raising: a fragment may
    legitimately name a variable a different call site supplies, and
    `check_09_placeholder_echo` plus the parity tests are what catch a genuinely
    unfilled one.
    """
    if not variables:
        return text
    return _PLACEHOLDER_RE.sub(
        lambda m: str(variables[m.group(1)]) if m.group(1) in variables else m.group(0),
        text,
    )


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


def _seam_join(frags: list[tuple[str, str, bool]]) -> str:
    """Assemble parts, each declaring the seam that precedes it.

    `frags` is (text, seam, keep_trailing). Trailing newlines are dropped unless
    the fragment declares them content; leading blank lines are always kept, so
    a seam WIDER than one blank line lives visibly in the fragment file.

    The separator belongs to the renderer, not to the fragment: a fragment read
    from a file carries the file's own trailing newline, so a bare
    ``"\n\n".join`` emits ``\n\n\n`` at every boundary and a trailing newline at
    the end. Against the live judge prompt that was +6 blank lines and +1
    terminator -- 5077 bytes rendered against 5070 live.

    The goldens could not have caught that. They were captured FROM the
    renderer, so they encode its own join byte for byte and stay green while
    every boundary is wrong. Only parity against the live builder sees it, which
    is the argument for Phase 1 existing at all (0089 §4).

    Nor could a single seam width serve every tier: see `Fragment.seam`.
    """
    out = ""
    for i, (text, seam, keep) in enumerate(frags):
        body = text if keep else text.rstrip("\n")
        if not body.strip("\n"):
            continue
        if not out:
            out = body.lstrip("\n")
            continue
        out += ("\n" if seam == "tight" else "\n\n") + body
    return out


def _join(parts) -> str:
    """Seamless assembly for callers with plain strings (slots, wrapped blocks)."""
    return _seam_join([(p, "blank", False) for p in parts])


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

    sys_text = _seam_join([(_fill(f.text, spec.variables), f.seam, f.keep_trailing)
                           for f in sys_frags])
    if len(usr_frags) == 1 and usr_frags[0].verbatim and not spec.slots:
        usr_text = _fill(usr_frags[0].text, spec.variables)
    else:
        usr_seams = [(_fill(f.text, spec.variables), f.seam, f.keep_trailing)
                     for f in usr_frags]
        usr_seams += [(wrap(s, nonce), "blank", False) for s in spec.slots]
        usr_text = _seam_join(usr_seams)

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
