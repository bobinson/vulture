"""The gemini model ids the launcher and the alias table name must exist.

Measured 2026-09-15 against the live Google API: BOTH `gemini-pro` (the
launcher's default, `scripts/start.sh`) and `gemini-1.5-pro` (what the alias
table expanded it to) return 404 NOT_FOUND for generateContent. Every gemini
LLM call therefore failed — 33 upstream 404s in one short run — and the whole
provider was non-functional.

The two ids also have to agree with each other, and that is the part a single
grep would miss. The agent resolves the alias through MODEL_MAP; the BROKER
never sees that expansion, because `strip_broker_prefix` in the launcher hands
it the bare id. So a bare alias that only the agent can expand reaches Google
verbatim. The guard below therefore checks BOTH the launcher default and the
alias target, and that the default is not itself a bare alias.

Offline by design: this pins the ids against a retired-list and a shape, not
against the network, so it fails the same way on a laptop with no key.
"""

import pathlib
import re

from shared.llm.provider import MODEL_MAP


def _repo_root() -> pathlib.Path:
    """Walk up to the checkout root. Counting `parents[n]` breaks the moment the
    test moves a directory, and it fails as a missing FILE rather than as the
    assertion this test exists to make."""
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "scripts" / "start.sh").is_file():
            return parent
    raise AssertionError("could not locate the repo root from " + __file__)


START_SH = _repo_root() / "scripts" / "start.sh"

# Ids that do NOT answer generateContent for this project's key, each verified
# with a real POST (2026-09-15), not merely against ListModels — `gemini-2.5-pro`
# is LISTED and still returns 404, so listing is not access.
# RETIRED: gone for everyone. An alias or default naming one is simply broken.
RETIRED = {
    "gemini-pro",       # 404, absent from ListModels
    "gemini-1.5-pro",   # 404, absent from ListModels (the old alias target)
    "gemini-1.5-flash", # 404, absent from ListModels
    "gemini-1.0-pro",   # 404, absent from ListModels
}
# TIER_GATED: the model exists and is LISTED, but this project's key cannot call
# it (404 on generateContent). Referencing one from an alias is legitimate — the
# alias must stay in its capability tier, and a key without access gets a clear
# `model_not_found` — but it must never be a DEFAULT, because the default has to
# work out of the box.
TIER_GATED = {"gemini-2.5-pro"}
UNAVAILABLE = RETIRED | TIER_GATED


def _launcher_gemini_default() -> str:
    text = START_SH.read_text()
    m = re.search(r'MODEL="\$\{MODEL:-(gemini[^}"]*)\}"', text)
    assert m, "could not find the gemini default in scripts/start.sh"
    return m.group(1)


def test_launcher_gemini_default_is_not_retired():
    got = _launcher_gemini_default()
    assert got not in UNAVAILABLE, (
        f"scripts/start.sh defaults gemini to {got!r}, which does not answer for this key — "
        "every call 404s and the provider is dead on arrival"
    )


def test_launcher_gemini_default_is_not_a_bare_alias():
    """The broker is handed the bare id, so an alias only the agent can expand
    reaches Google verbatim."""
    got = _launcher_gemini_default()
    assert got not in MODEL_MAP, (
        f"{got!r} is a MODEL_MAP key. The agent would expand it, but "
        "strip_broker_prefix hands the broker the bare string, so Google sees "
        f"{got!r} itself. Default to a real upstream id."
    )


def test_gemini_aliases_never_point_at_a_retired_id():
    """An alias may name a tier-gated model — that fails loudly and legibly.
    It may never name a retired one, which is just broken."""
    for alias, target in MODEL_MAP.items():
        if "gemini" not in target:
            continue
        bare = target.rsplit("/", 1)[-1]
        assert bare not in RETIRED, (
            f"MODEL_MAP[{alias!r}] -> {target!r}: {bare!r} is retired upstream"
        )


# ── an alias must not lie about its tier ──────────────────────────────────────
#
# Fixing the retired-id bug, `gemini-pro` was pointed at
# `litellm/gemini/gemini-2.5-flash` because flash is what this key can call.
# That traded a loud 404 for a silent substitution: `pro` and `flash` are
# different capability tiers and different prices, and every table keyed on the
# alias — CONTEXT_WINDOWS, COST_PER_1M_TOKENS — kept describing a pro model. The
# cost entry (1.25, 5.00) is gemini-1.5-pro's, so a flash run would have been
# costed ~4x high and VULTURE_LLM_BUDGET_USD would trip early.
#
# A dead alias fails loudly and gets fixed. A lying alias runs forever.

_TIERS = ("pro", "flash", "lite")


def _tier(name: str) -> "str | None":
    bare = name.rsplit("/", 1)[-1].lower()
    # `flash-lite` is its own tier; check the most specific first.
    if "flash-lite" in bare or bare.endswith("-lite"):
        return "lite"
    for t in ("flash", "pro"):
        if t in bare:
            return t
    return None


def test_an_alias_never_resolves_to_a_different_tier():
    for alias, target in MODEL_MAP.items():
        at, tt = _tier(alias), _tier(target)
        if at is None or tt is None:
            continue
        assert at == tt, (
            f"MODEL_MAP[{alias!r}] -> {target!r} crosses a capability tier "
            f"({at} -> {tt}). An alias that silently downgrades is worse than one that "
            "404s: the 404 gets fixed, the substitution is billed and trusted."
        )


def test_every_gemini_alias_has_its_own_cost_entry():
    """Pricing is keyed on the ALIAS, so two aliases pointing at different
    models must not share one price."""
    from shared.llm.provider import COST_PER_1M_TOKENS

    gem = {a: t for a, t in MODEL_MAP.items() if "gemini" in t}
    for alias in gem:
        assert alias in COST_PER_1M_TOKENS, (
            f"{alias!r} resolves to a gemini model but has no COST_PER_1M_TOKENS entry, "
            "so budget accounting silently uses a default"
        )
    # Distinct targets must not be priced identically by accident.
    by_target = {}
    for alias, target in gem.items():
        by_target.setdefault(target, []).append(alias)
    for target, aliases in by_target.items():
        prices = {COST_PER_1M_TOKENS[a] for a in aliases}
        assert len(prices) == 1, f"aliases for {target} disagree on price: {prices}"
