"""Feature 0102 — the ``ast_v1`` corpus group is VERIFIED for the three
families the AST tier owns: CWE-22 path traversal, CWE-918 SSRF and CWE-78 OS
command injection.

The group is scored by the same deterministic runner and the same strict bar as
every other corpus group (``corpus_runner.score_with`` over
``run_deterministic``: file-level recall over the positives, file-level
false-positive rate over the clean twins, banded by ``apply_gates``). For each
family: recall 1.0, false-positive rate 0.0, and at least three fixtures on
each side.

RED until the AST tier owns the three check ids. Most positives are flows a
line-local pattern cannot follow (a request value carried through assignments,
helpers, closures or callbacks before it reaches the sink, or a sink the regex
vocabulary does not know), and most clean twins are where a line-local pattern
over-reports (a sanitiser, a guard, a shadowing local definition). A failure
names the rows the deterministic tiers got wrong.

The fragment is ``manifest.d/_ast_v1.yaml`` while the group is RED and
``ast_v1.yaml`` once the AST tier owns the check ids; ``_ast_v1.fragment()``
reads whichever exists, so the rename needs no edit here.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable, Mapping
from typing import Any

import corpus_runner
import pytest

from tests import _ast_v1

FAMILIES = ("22", "918", "78")
MIN_FIXTURES = 3

# The strict corpus bar, stated literally rather than read from gates.yaml.
GATES = corpus_runner.Gates(
    defaults={"min_fixtures": MIN_FIXTURES, "min_recall": 1.0, "max_fp_rate": 0.0},
    overrides={},
)

# One detection pass per fixture: scoring and the failure message share it.
detect = functools.cache(corpus_runner.run_deterministic)

Entry = Mapping[str, Any]


def _verified(cwe: str, score: corpus_runner.CweScore) -> bool:
    return corpus_runner.apply_gates({cwe: score}, GATES)[cwe] == "VERIFIED"


def _wrong(entry: Entry) -> bool:
    """The deterministic tiers disagree with the row's expectation."""
    fired = f"CWE-{entry['cwe']}" in detect(str(corpus_runner.FIXTURES_DIR / entry["file"]))
    return fired != (entry["expectation"] == "positive")


def _wrong_rows(entries: Iterable[Entry], cwe: str) -> str:
    """One ``<expectation>: <file>`` line per row of ``cwe`` the tiers got wrong.

    A string, not a list: pytest truncates the repr of a container message.
    """
    return "\n".join(
        f"  {e['expectation']}: {e['file']}" for e in entries if str(e["cwe"]) == cwe and _wrong(e)
    )


@pytest.fixture(scope="module")
def scores() -> dict[str, corpus_runner.CweScore]:
    """One deterministic pass over the whole group."""
    return corpus_runner.score_with(list(_ast_v1.load_group()), detect)


def test_group_holds_only_the_ast_families(scores: dict[str, corpus_runner.CweScore]) -> None:
    assert set(scores) == set(FAMILIES), sorted(scores, key=int)


@pytest.mark.parametrize("cwe", FAMILIES)
def test_ast_v1_group_is_verified(scores: dict[str, corpus_runner.CweScore], cwe: str) -> None:
    score = scores.get(cwe)
    assert score is not None, f"no CWE-{cwe} row in manifest.d/{_ast_v1.fragment()}.yaml"
    assert _verified(cwe, score), f"{score}\nwrong rows:\n{_wrong_rows(_ast_v1.load_group(), cwe)}"
