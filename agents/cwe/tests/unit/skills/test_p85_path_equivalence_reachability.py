"""P8.5 — path-equivalence CWEs must be visible to the reachability extractor.

``path_equivalence_check`` builds its ``category`` with an f-string
(``f"CWE-{cwe_id}"``), which is correct at runtime but invisible to
``tests/corpus/report_coverage.skill_category_cwe_ids()`` — the attestation's
extractor scans skill SOURCE for the literal shapes ``"category": "CWE-N"`` /
``category="CWE-N"``. Every id this skill emits therefore read as unreachable.

Three assertions, failing for different reasons:

1. the real consumer (``report_coverage``) sees every emitted id;
2. the static declaration and the variant table agree EXACTLY in both
   directions, so the declaration can neither under- nor over-claim;
3. runtime output is unchanged — the ``category`` on every emitted row is
   still exactly ``f"CWE-{cwe_id}"`` for the variant that produced it.
"""

import sys
import tempfile
from pathlib import Path

import pytest

from cwe_agent.skills import path_equivalence_check as pec
from cwe_agent.skills.path_equivalence_check import check_path_equivalence

_CORPUS = Path(__file__).resolve().parents[2] / "corpus"
if str(_CORPUS) not in sys.path:
    sys.path.insert(0, str(_CORPUS))

import report_coverage as rc  # noqa: E402

# One line per variant in ``_VARIANTS``; every id below is emitted by a real
# scan of this fixture (asserted in test_runtime_categories_are_unchanged).
_FIXTURE = """\
open("/var/log/app..")
open("/var/log/app.")
open("/var/log/app ")
open("data/dir/")
open("C:\\\\tmp\\\\")
open("/var//")
open("//srv/data")
open("/a//b")
open("/a/./b")
open("../etc/passwd")
open("/var/my file")
open("/var/*.log")
open("..%2fetc/passwd")
open("..%252fetc/passwd")
open("%2e%2e/etc")
open("%2e%2e%2fetc")
open("..%c0%afetc")
open("..%00.png")
open("..\\\\windows\\\\x")
"""


def _variant_ids() -> set[str]:
    return {cwe_id for cwe_id, _pat, _label, _sev in pec._VARIANTS}


def test_emitted_categories_are_statically_discoverable():
    """The attestation's own extractor must see every id this skill emits."""
    missing = sorted(_variant_ids() - rc.skill_category_cwe_ids(), key=int)
    assert not missing, (
        "path_equivalence_check emits these CWE-ids at runtime but the "
        f"reachability extractor cannot see them statically: {missing}. "
        'The literal "category": "CWE-N" must appear in the skill source.'
    )


def test_static_declaration_matches_the_variant_table():
    """The declaration may neither under-claim nor over-claim."""
    declared = {
        cwe_id: row["category"] for cwe_id, row in pec._CATEGORY_ROWS.items()
    }
    assert set(declared) == _variant_ids()
    assert declared == {cwe_id: f"CWE-{cwe_id}" for cwe_id in _variant_ids()}


@pytest.fixture(scope="module")
def scanned_findings() -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "sample.py").write_text(_FIXTURE)
        return check_path_equivalence(d)["findings"]


def test_runtime_categories_are_unchanged(scanned_findings):
    """Every emitted row still carries exactly ``f"CWE-{cwe_id}"``."""
    assert scanned_findings
    for finding in scanned_findings:
        cwe_id = finding["check_id"].rsplit("_", 1)[1]
        assert finding["category"] == f"CWE-{cwe_id}"


def test_fixture_exercises_every_variant(scanned_findings):
    """Guards the parity test above from silently covering only a subset."""
    seen = {f["category"] for f in scanned_findings}
    assert seen == {f"CWE-{i}" for i in _variant_ids()}
