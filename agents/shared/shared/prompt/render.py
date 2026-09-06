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
    # The per-request token this render's markers carry, "" when it wrapped
    # nothing. Exposed (item 4.3) because a request is usually more than one
    # render: the judge builds its user turn before its tool loop starts, and
    # two renders minting two tokens would put two equally valid delimiters in
    # front of the model, which makes "only the token that opened a block can
    # close it" unverifiable by the reader it is addressed to.
    nonce: str = ""

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


def _rule_system_role(st: RenderState, sys_frags: list[Fragment],
                      usr_frags: list[Fragment]) -> tuple[list[Fragment], list[Fragment]]:
    """Rule 1: a profile with no system role gets everything in the user turn.

    Split from `_rule_mirror` rather than written as the one `if`/`elif` this
    replaces, because the module contract above is one rule per function. The
    split is exact, not merely equivalent-looking: this rule EMPTIES
    `sys_frags`, so the mirror rule that runs next finds nothing to mirror and
    is a no-op. The `elif` expressed that same exclusion by computing the
    mirrored list BEFORE the collapse and then declining to use it; ordered
    rules need no such lookahead.
    """
    if st.profile.system_role:
        return sys_frags, usr_frags
    return [], sys_frags + usr_frags


def _rule_mirror(st: RenderState, sys_frags: list[Fragment],
                 usr_frags: list[Fragment]) -> tuple[list[Fragment], list[Fragment]]:
    """Rule 2: also place SYSTEM+USER_MIRROR fragments at the head of the user turn.

    Why duplicate rather than move: see `Role.SYSTEM_USER_MIRROR`. A gateway
    that silently drops an unsupported system role is undetectable from here,
    so anything the response depends on is mirrored instead of trusted to
    survive the hop.

    Takes `st` it does not read, so every rule in the pipeline has the same
    shape and `_adapt` reads as a list of rules rather than a list of
    call-signature exceptions.
    """
    mirrored = [f for f in sys_frags if f.role is Role.SYSTEM_USER_MIRROR]
    return sys_frags, mirrored + usr_frags


def _adapt(st: RenderState, sys_frags: list[Fragment],
           usr_frags: list[Fragment]) -> tuple[list[Fragment], list[Fragment]]:
    """The ADAPT pipeline. Order matters; a rule that does not apply is a no-op.

    Stance filtering runs before placement for a reason that is easy to lose:
    `_rule_mirror` selects out of `sys_frags`, so a mirrored fragment dropped
    by `_rule_json_contract` must already be gone, or the turn the profile
    cannot honour reappears in the user turn.
    """
    sys_frags = _rule_json_contract(st, sys_frags)
    sys_frags = _rule_language(st, sys_frags)
    sys_frags, usr_frags = _rule_system_role(st, sys_frags, usr_frags)
    return _rule_mirror(st, sys_frags, usr_frags)


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
    for text, seam, keep in frags:
        body = _body(text, keep)
        if not body.strip("\n"):
            continue
        if not out:
            out = body.lstrip("\n")
            continue
        out += _sep(seam) + body
    return out


def _body(text: str, keep: bool) -> str:
    """One part's bytes: trailing newlines are an editor artefact unless declared.

    See `Fragment.keep_trailing` — for 38 of 40 fragments they are an artefact,
    and for two they are content the live prompt carries.
    """
    return text if keep else text.rstrip("\n")


def _sep(seam: str) -> str:
    """The separator a part's declared seam puts in FRONT of it.

    Two widths, because the live GENERATE prompt has both: `\\n` where
    `_quote_contract_suffix()` returns `f"\\n{...}"`, `\\n\\n` everywhere else.
    An unknown value reads as the default rather than raising — `parse_fragment`
    already rejects one at import, so nothing unvalidated reaches here.
    """
    return "\n" if seam == "tight" else "\n\n"


def _join(parts) -> str:
    """Seamless assembly for callers with plain strings (slots, wrapped blocks)."""
    return _seam_join([(p, "blank", False) for p in parts])


def _resolve_nonce(nonce: str | None, spec) -> str:
    """This render's marker token: the caller's, or a fresh one, or none.

    `None` and `""` are deliberately different. Omitting the argument asks the
    renderer to mint a token; passing `""` says "this request has no token",
    which `wrap` honours literally — the markers come out as `<<<KIND:` with
    nothing after the colon, unforgeable by nobody. That is a deterministic
    render for a caller that wants one, never a default: a single falsy test
    here would silently turn an explicit empty string into a fresh random
    token, or a forgotten argument into no protection at all.

    Extracted rather than inlined so `render` does not grow a branch: it is a
    C-grade function already (16 by `radon` before item 4.3), and the plan's
    cross-phase rule is that no new outlier appears under `shared/prompt/`.
    """
    if nonce is not None:
        return nonce
    return new_nonce() if spec.slots else ""


def _seams(frags: list[Fragment], variables: dict) -> list[tuple[str, str, bool]]:
    """Interpolate each fragment and pair it with the seam it declares.

    The one place `_fill` meets `Fragment.seam`, so the two turns cannot drift
    apart: the system turn and the composed user turn were separate list
    comprehensions saying the same thing.
    """
    return [(_fill(f.text, variables), f.seam, f.keep_trailing) for f in frags]


def _is_verbatim_turn(usr_frags: list[Fragment], spec) -> bool:
    """Whether the user turn is one whole-turn template rather than sections.

    See `Fragment.verbatim`: a template's bytes pass through untouched, and its
    own trailing newline is part of the message. All three conditions are
    load-bearing — a second fragment or any slot makes the turn COMPOSED, and
    the strip rule for a section is not the strip rule for a template.
    """
    return len(usr_frags) == 1 and usr_frags[0].verbatim and not spec.slots


def _user_text(usr_frags: list[Fragment], spec, nonce: str) -> str:
    """The user turn: a verbatim template, or fragments followed by wrapped slots."""
    if _is_verbatim_turn(usr_frags, spec):
        return _fill(usr_frags[0].text, spec.variables)
    parts = _seams(usr_frags, spec.variables)
    parts += [(wrap(s, nonce), "blank", False) for s in spec.slots]
    return _seam_join(parts)


def _messages(sys_text: str, usr_text: str) -> list[dict]:
    """Chat-message form. An empty turn is OMITTED, never sent as an empty string.

    A gateway is entitled to reject a zero-length message, and a model that
    accepts one still spends a turn boundary on nothing.
    """
    out: list[dict] = []
    if sys_text:
        out.append({"role": "system", "content": sys_text})
    if usr_text:
        out.append({"role": "user", "content": usr_text})
    return out


def render(spec, profile: ModelProfile, *, mode: Mode = Mode.TRANSCRIBE,
           nonce: str | None = None) -> RenderedPrompt:
    """Compose `spec` for `profile`. Pure: no env reads, no I/O.

    `nonce` binds one request's marker token across several renders (item 4.3);
    omit it and a render that wraps anything mints its own. Minting stays the
    default because the failure modes are asymmetric: a caller who forgets to
    pass one gets an unshared-but-unforgeable token, while a caller who has to
    supply one to get any token at all eventually supplies a constant.

    The body is a pipeline, not a procedure: it resolves the fragment lists,
    hands them to `_adapt` when the mode asks for it, and turns what comes back
    into text. Every decision above one branch lives in a named function, so
    the ADAPT rules can be read — and tested — one at a time.
    """
    sys_frags = _texts(spec.fragments)
    usr_frags = _texts(spec.user_fragments)
    nonce = _resolve_nonce(nonce, spec)
    adapt = mode is Mode.ADAPT

    if adapt:
        st = RenderState(system=(), user=(), tools=spec.tools, profile=profile)
        sys_frags, usr_frags = _adapt(st, sys_frags, usr_frags)

    sys_text = _seam_join(_seams(sys_frags, spec.variables))
    usr_text = _user_text(usr_frags, spec, nonce)
    body = sys_text + usr_text
    return RenderedPrompt(
        instructions=sys_text, user=usr_text,
        messages=_messages(sys_text, usr_text),
        tool_specs=None,
        response_format=_response_format(profile, bool(spec.tools)) if adapt else None,
        output_budget_hint=_budget(profile, len(body)),
        fingerprint=hashlib.sha256(body.encode("utf-8")).hexdigest()[:16],
        fragments=tuple(spec.fragments) + tuple(spec.user_fragments),
        nonce=nonce,
    )
