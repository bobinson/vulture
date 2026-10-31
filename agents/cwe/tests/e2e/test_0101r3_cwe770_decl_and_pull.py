"""Feature 0101 revision 3 -- CWE-770: typed body declarations and sized reads.

Two gaps found by the revision-3 adversarial review of the CWE-770 rule:

* A statically typed local declared inside a loop body (``List<String> parts =
  new ArrayList<>();``) lives one iteration, exactly like ``var parts = ...``,
  but only the keyword forms were read as declarations, so a Java/C++ body that
  starts a fresh collection per line was reported (precision).
* A read whose size is a numeric argument (``os.read(fd, 4096)``) and a
  receive/read helper named with a word prefix (``socket_read($sock, 2048)``,
  ``socket_recv(...)``) were not read as pulls, so an infinite loop that pulls
  in its body and grows a collection was missed (recall).

The fixtures carry ``EXPECT-NEXT`` markers and are scanned from a neutral copy,
because the rule skips test paths.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.resource_check import check_resource_management
from tests.e2e._0101_markers import mismatches, neutral_copy, parse_tree

FIXTURES = Path(__file__).parent / "fixtures" / "0101r3_cwe770"
CATEGORY = "CWE-770"


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, list, list[dict]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe770r3"))
    findings = [f for f in check_resource_management(str(root))["findings"]
                if f["category"] == CATEGORY]
    return root, parse_tree(root), findings


def test_every_marked_site_has_its_verdict(corpus: tuple[Path, list, list[dict]]) -> None:
    root, sites, findings = corpus
    assert len(sites) == 9
    assert mismatches(findings, sites, CATEGORY, root) == []


def test_nothing_is_reported_off_a_marked_site(corpus: tuple[Path, list, list[dict]]) -> None:
    root, sites, findings = corpus
    marked = {(s.rel, s.line) for s in sites if s.verdict == "finding"}
    emitted = {(str(Path(f["file_path"]).relative_to(root)) if Path(f["file_path"]).is_absolute()
                else f["file_path"], int(f["line_start"])) for f in findings}
    assert emitted == marked
