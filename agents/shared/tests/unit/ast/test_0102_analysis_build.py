"""Feature 0102, A35 and A38 (LLD §5, §6.2, §8.4, §8.7; A28 (3)): what a built analysis is.

A38 builds the analysis EAGERLY: ``FileModel.analysis()`` computes the candidates of every
family the model's language owns, so ``candidates(family)`` is a lookup and the analysis'
``bytes_estimate`` (A35) is what a consumer leaves cached. These tests pin the three
consequences the other modules leave open:

* the build computes the OWNED families only (D-H: C and C++ own path and command, so the
  AST tier builds no request candidate there, however a call is spelled);
* a diagnostic query (``origins``, ``guards_for``, ``summary``) answers what the build
  answered: a callee's summary signatures are capped in the order its calls are met
  (``MAX_SUMMARY_SIGNATURES``, §8.4), so a query must meet them in the build's order, never
  in its own;
* a per-file fact is counted once (A28 (3)): a diagnostic query adds to ``tallies`` only
  what the build never met, never a fact the build already counted.

Every model is a fresh one (``model_of``), since the order of the queries is the subject.
"""

from __future__ import annotations

import pytest

from shared.ast import limits
from tests.unit.ast._analysis import analysis_of, call_at, external, model_of, unknown
from tests.unit.ast.test_0102_flow_rules import _summed

pytestmark = pytest.mark.usefixtures("real_pool")

# A request-word callee and a command sink on ``argv`` (C4: ``main``'s argv is external).
_C_PROGRAM = """\
int main(int argc, char **argv) {
  fetch(argv[1]);
  urlopen(argv[1]);
  system(argv[1]);
  return 0;
}
"""


@pytest.mark.parametrize("lang", ["c", "cpp"])
def test_the_build_computes_only_the_families_the_language_owns(lang: str) -> None:
    """A38, D-H: a C or C++ model's analysis has no request candidate — the language owns
    path and command only — while its command sink is a candidate as on any language."""
    analysis = analysis_of(model_of(_C_PROGRAM, lang))

    command = [flow.sink_line for flow in analysis.candidates("command")]

    assert (analysis.candidates("request"), command) == ((), [4])


# ``relay`` is a local identity function: each call is summarised under its argument's
# origins, at most MAX_SUMMARY_SIGNATURES distinct signatures (§8.4). Four calls reach no
# sink and come first; the path sink's call, a fifth signature, comes last.
_SIGNATURES = ("req", "argv", "mystery", "req + argv", "req + mystery")
_RELAYS = "".join(f"  sink(relay({argument}));\n" for argument in _SIGNATURES[:-1])
_RELAYED = (
    "function relay(p) {\n  return p;\n}\n"
    f"function h(req) {{\n{_RELAYS}  fs.readFileSync(relay({_SIGNATURES[-1]}));\n}}\n"
)


def test_a_diagnostic_query_answers_what_the_build_answered() -> None:
    """§8.4, A38: the build meets only the path sink's ``relay`` call, its first signature,
    so the candidate's origins are its argument's. Asking the analysis for the four other
    calls first, then for that argument, answers the candidate's origins — never the
    ``summary_cap`` a fifth signature met in the query's own order would give."""
    assert len(_SIGNATURES) == limits.MAX_SUMMARY_SIGNATURES + 1
    model = model_of(_RELAYED, "js")
    analysis = analysis_of(model)
    (flow,) = analysis.candidates("path")

    for nth in range(len(_SIGNATURES) - 1):
        analysis.origins(call_at(model, "relay", nth=nth))

    expected = {external("request"), unknown("unresolved")}
    assert (flow.origins, analysis.origins(flow.arg)) == (expected, expected)


def test_a_diagnostic_query_never_counts_a_build_fact_again() -> None:
    """A28 (3): a path sink summing MAX_ORIGINS + 1 distinct origins overflows once, at
    build; asking the analysis for that argument again leaves ``origin_overflow`` at one."""
    model = model_of(f"function h(req) {{\n  fs.readFileSync({_summed(limits.MAX_ORIGINS + 1)});\n}}\n", "js")
    analysis = analysis_of(model)
    (flow,) = analysis.candidates("path")
    built = analysis.tallies["origin_overflow"]

    analysis.origins(flow.arg)
    analysis.guards_for(flow.sink, flow.arg)

    assert (built, analysis.tallies["origin_overflow"]) == (1, 1)


def test_a_diagnostic_query_counts_what_the_build_never_met() -> None:
    """A28 (3): a call that is no sink is never met by the build; asking for its argument is
    what meets the overflow, and it is counted then, once."""
    model = model_of(f"function h(req) {{\n  sink({_summed(limits.MAX_ORIGINS + 1)});\n}}\n", "js")
    analysis = analysis_of(model)
    built = analysis.tallies.get("origin_overflow", 0)

    arg = model.args(call_at(model, "sink"))[0]
    analysis.origins(arg)
    analysis.origins(arg)

    assert (built, analysis.tallies["origin_overflow"]) == (0, 1)
