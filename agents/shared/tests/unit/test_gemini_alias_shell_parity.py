"""The launcher's alias expansion must cover every alias, not the one that bit us.

`gemini-pro` is an ALIAS, not a Google model id: MODEL_MAP points it at
`gemini-2.5-pro`. The broker is handed a BARE id and cannot consult MODEL_MAP,
so a bare alias reaches Google verbatim and 404s. scripts/start.sh therefore
expands it in normalize_model — but it did so with a single hardcoded
comparison against "gemini-pro", which means the very next alias reproduces the
identical bug. `gemini-flash` was added in the same change that fixed
`gemini-pro` and was born broken for exactly this reason.

This test is the guard: every gemini alias Python knows about must be expanded
by the shell. It fails on the ADDITION of an alias, which is the moment the
author can still fix it cheaply.
"""

from __future__ import annotations

import re
from pathlib import Path

from shared.llm.provider import MODEL_MAP

START_SH = Path(__file__).resolve().parents[4] / "scripts" / "start.sh"


def _gemini_aliases() -> dict[str, str]:
    """Aliases whose KEY is not already the concrete Google id."""
    out = {}
    for alias, target in MODEL_MAP.items():
        if not target.startswith("litellm/gemini/"):
            continue
        concrete = target.rsplit("/", 1)[-1]
        if alias != concrete:
            out[alias] = concrete
    return out


def _shell_alias_table() -> dict[str, str]:
    """Parse the `alias)  _nm=concrete ;;` arms out of normalize_model."""
    body = START_SH.read_text(encoding="utf-8")
    start = body.index("normalize_model()")
    end = body.index("strip_broker_prefix()")
    return dict(
        re.findall(
            r'^\s*([A-Za-z0-9._-]+)\)\s*_nm="([A-Za-z0-9._-]+)"\s*;;',
            body[start:end],
            re.MULTILINE,
        )
    )


def test_every_gemini_alias_is_expanded_by_the_launcher() -> None:
    aliases = _gemini_aliases()
    assert aliases, "fixture is stale: MODEL_MAP has no gemini aliases at all"
    shell = _shell_alias_table()
    missing = sorted(set(aliases) - set(shell))
    assert not missing, (
        f"{missing} reach the broker as a bare id Google does not have, and 404. "
        f"Add each to normalize_model's gemini alias table in scripts/start.sh. "
        f"Shell knows: {sorted(shell)}"
    )


def test_the_shell_expands_each_alias_to_what_python_resolves_it_to() -> None:
    aliases = _gemini_aliases()
    shell = _shell_alias_table()
    wrong = {a: (shell[a], aliases[a]) for a in aliases if a in shell and shell[a] != aliases[a]}
    assert not wrong, (
        "the launcher and MODEL_MAP disagree about what an alias means, so a run "
        f"is priced and context-sized as one model and executed as another: {wrong}"
    )


def test_the_shell_invents_no_alias_python_does_not_know() -> None:
    """The reverse direction: a shell-only alias is mispriced and mis-sized,
    because pricing and CONTEXT_WINDOWS are keyed on the Python side."""
    extra = sorted(set(_shell_alias_table()) - set(_gemini_aliases()))
    assert not extra, f"launcher expands aliases MODEL_MAP has never heard of: {extra}"
