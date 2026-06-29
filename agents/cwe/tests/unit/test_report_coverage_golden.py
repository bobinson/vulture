"""T22 — Feature 0057 Phase 6 (P6a / R16): the committed VERIFIED_CWES.md
golden is byte-identical to a fresh in-memory regeneration.

``report_coverage.build_markdown()`` is the SINGLE source of truth for the
attestation document ``tests/corpus/VERIFIED_CWES.md``. CI regenerates it and
diffs against the committed file; a STALE golden (committed content drifted
from what the venv now produces) MUST fail this test, which fails CI.

This mirrors the established golden pattern (regenerate-in-memory, read the
committed file, assert byte-equality up to a trailing newline). It deliberately
does NOT assert a literal N — the count is reproduced from the VERIFIED bucket,
never hand-typed.

RED until ``tests/corpus/report_coverage.py`` exists with ``build_markdown()``
AND the committed ``tests/corpus/VERIFIED_CWES.md`` matches it.

``report_coverage`` is importable by its bare module name because
``tests/unit/conftest.py`` adds ``tests/corpus`` to ``sys.path``.
"""

from __future__ import annotations

from pathlib import Path


import report_coverage  # noqa: E402 — sys.path injected by conftest

_CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
_GOLDEN = _CORPUS_DIR / "VERIFIED_CWES.md"


def _normalize(text: str) -> str:
    """Normalize a single trailing newline so the comparison is robust to an
    editor's final-newline policy, but otherwise byte-exact."""
    return text.rstrip("\n") + "\n"


class TestVerifiedCwesGolden:
    def test_build_markdown_returns_nonempty_markdown(self):
        md = report_coverage.build_markdown()
        assert isinstance(md, str)
        assert md.strip(), "build_markdown() must return non-empty content"

    def test_golden_file_exists(self):
        assert _GOLDEN.is_file(), (
            f"committed attestation golden missing: {_GOLDEN}. "
            "report_coverage.main() / CI must write it."
        )

    def test_committed_golden_matches_regeneration(self):
        """The committed VERIFIED_CWES.md MUST equal a fresh regeneration.

        A stale golden (someone edited prose by hand, or the gate result moved
        and the file was not regenerated) fails here -> CI fails.
        """
        regenerated = _normalize(report_coverage.build_markdown())
        committed = _normalize(_GOLDEN.read_text(encoding="utf-8"))
        assert committed == regenerated, (
            "VERIFIED_CWES.md is STALE. Regenerate it via the venv:\n"
            "  agents/.venv/bin/python "
            "agents/cwe/tests/corpus/report_coverage.py\n"
            "and commit the result."
        )

    def test_golden_states_N_from_verified_bucket(self):
        """The golden header states ``N = <count>`` and that count is the
        number of VERIFIED rows the gate produced (reproduced, not asserted as
        a literal here)."""
        from corpus_runner import build_report  # bare import via conftest path

        n = build_report()["n"]
        committed = _GOLDEN.read_text(encoding="utf-8")
        assert f"N = {n}" in committed, (
            f"golden must carry the reproduced gate count 'N = {n}'"
        )
