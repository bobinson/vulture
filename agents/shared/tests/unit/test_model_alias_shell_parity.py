"""The launcher's alias expansion must cover every alias, not the one that bit us.

`gemini-pro` and `claude-sonnet` are ALIASES, not upstream model ids: MODEL_MAP
points each at a real one. The broker is handed a BARE id and cannot consult
MODEL_MAP, so a bare alias reaches Google or Anthropic verbatim and 404s.
scripts/lib/models.sh therefore expands them in normalize_model — once with a
single hardcoded comparison against "gemini-pro", which meant the very next
alias reproduced the identical bug: `gemini-flash` was added in the same change
that fixed `gemini-pro` and was born broken. `claude-sonnet` was never expanded
at all, so `vulture.sh dev anthropic` with no model sent `claude-sonnet` to
Anthropic.

This test is the guard: every alias Python knows about, for every provider the
launcher routes natively, must be expanded by the shell to the same id. It fails
on the ADDITION of an alias, which is the moment the author can still fix it
cheaply.
"""

from __future__ import annotations

import re
from pathlib import Path

from shared.llm.provider import MODEL_MAP

MODELS_SH = Path(__file__).resolve().parents[4] / "scripts" / "lib" / "models.sh"

# The providers whose models the launcher routes through LiteLLM's native
# provider, and so whose aliases it must expand itself.
NATIVE_PREFIXES = ("litellm/gemini/", "litellm/anthropic/")


def _python_aliases() -> dict[str, str]:
    """Aliases whose KEY is not already the concrete upstream id."""
    out = {}
    for alias, target in MODEL_MAP.items():
        if not target.startswith(NATIVE_PREFIXES):
            continue
        concrete = target.rsplit("/", 1)[-1]
        if alias != concrete:
            out[alias] = concrete
    return out


def _shell_alias_table() -> dict[str, str]:
    """Parse the `alias)  _nm="concrete" ;;` arms out of normalize_model."""
    body = MODELS_SH.read_text(encoding="utf-8")
    start = body.index("normalize_model()")
    end = body.index("strip_broker_prefix()")
    return dict(
        re.findall(
            r'^\s*([A-Za-z0-9._-]+)\)\s*_nm="([A-Za-z0-9._-]+)"\s*;;',
            body[start:end],
            re.MULTILINE,
        )
    )


def test_fixture_covers_each_native_provider() -> None:
    aliases = _python_aliases()
    for prefix in NATIVE_PREFIXES:
        assert any(MODEL_MAP[a].startswith(prefix) for a in aliases), (
            f"fixture is stale: MODEL_MAP has no {prefix} alias at all"
        )


def test_every_alias_is_expanded_by_the_launcher() -> None:
    missing = sorted(set(_python_aliases()) - set(_shell_alias_table()))
    assert not missing, (
        f"{missing} reach the broker as a bare id the provider does not have, and "
        "404. Add each to normalize_model's alias table in scripts/lib/models.sh. "
        f"Shell knows: {sorted(_shell_alias_table())}"
    )


def test_the_shell_expands_each_alias_to_what_python_resolves_it_to() -> None:
    aliases = _python_aliases()
    shell = _shell_alias_table()
    wrong = {a: (shell[a], aliases[a]) for a in aliases if a in shell and shell[a] != aliases[a]}
    assert not wrong, (
        "the launcher and MODEL_MAP disagree about what an alias means, so a run "
        f"is priced and context-sized as one model and executed as another: {wrong}"
    )


def test_the_shell_invents_no_alias_python_does_not_know() -> None:
    """The reverse direction: a shell-only alias is mispriced and mis-sized,
    because pricing and CONTEXT_WINDOWS are keyed on the Python side."""
    extra = sorted(set(_shell_alias_table()) - set(_python_aliases()))
    assert not extra, f"launcher expands aliases MODEL_MAP has never heard of: {extra}"
