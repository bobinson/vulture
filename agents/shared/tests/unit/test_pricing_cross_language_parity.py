"""Two pricing tables, one budget. They must not disagree.

The Go broker reserves budget BEFORE a call (provider/pricing.go) and the
Python agent accounts for it AFTER (provider.COST_PER_1M_TOKENS). Both feed the
same VULTURE_LLM_BUDGET_USD cap, and the Go file's own header says it "mirrors"
the Python one — a mirror kept by hand, with nothing checking it.

It drifted. `gemini-pro` sat at (1.25, 5.00) in Go and (1.25, 10.00) in Python,
so the pre-flight reservation was HALF the real output rate: the cap engaged at
roughly twice the spend an operator set it to, and the under-reservation is
invisible because no error is raised — the run simply costs more than the
budget allowed. This test is what makes the mirror real.

Only keys present in BOTH tables are compared; each file legitimately prices
models the other never sees (local Ollama tags on one side, native-adapter ids
on the other).
"""

from __future__ import annotations

import re
from pathlib import Path

from shared.llm.provider import COST_PER_1M_TOKENS

PRICING_GO = (
    Path(__file__).resolve().parents[4]
    / "backend"
    / "internal"
    / "broker"
    / "provider"
    / "pricing.go"
)


def _go_prices() -> dict[str, tuple[float, float]]:
    body = PRICING_GO.read_text(encoding="utf-8")
    table = body[body.index("priceUSDPer1M = map[string][2]float64{") :]
    table = table[: table.index("\n}\n")]
    return {
        name: (float(inp), float(out))
        for name, inp, out in re.findall(
            r'"([^"]+)":\s*\{\s*([0-9.]+)\s*,\s*([0-9.]+)\s*\}', table
        )
    }


def test_the_go_and_python_pricing_tables_agree_where_they_overlap() -> None:
    go = _go_prices()
    assert go, f"parsed no prices out of {PRICING_GO} — the parser is stale, not the table"
    shared_keys = sorted(set(go) & set(COST_PER_1M_TOKENS))
    assert shared_keys, "fixture is stale: the two tables no longer share a single model"
    disagree = {
        k: {"go": go[k], "python": COST_PER_1M_TOKENS[k]}
        for k in shared_keys
        if go[k] != COST_PER_1M_TOKENS[k]
    }
    assert not disagree, (
        "the pre-flight reservation and the post-hoc accounting price the same "
        f"model differently, so VULTURE_LLM_BUDGET_USD is enforced at the wrong "
        f"spend: {disagree}"
    )


def test_an_alias_is_priced_as_the_model_it_resolves_to() -> None:
    """`gemini-pro` is an alias. Pricing it as anything but its target is the
    bug the alias fix was about, in the budget rather than the request."""
    from shared.llm.provider import MODEL_MAP

    go = _go_prices()
    wrong = {}
    for alias, target in MODEL_MAP.items():
        concrete = target.rsplit("/", 1)[-1]
        if alias == concrete or alias not in go or concrete not in go:
            continue
        if go[alias] != go[concrete]:
            wrong[alias] = {"alias": go[alias], concrete: go[concrete]}
    assert not wrong, f"alias priced differently from the model it resolves to: {wrong}"
