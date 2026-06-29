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

The second class (``TestCheckGoldenGate``) pins the ``check_golden()`` /
``--check`` STALENESS GATE (P5e / R17) — the load-bearing CI enforcement that
``make cwe-corpus`` runs. ``check_golden()`` is what FAILS a PR when the golden
drifts, so its three exit-code behaviours (current → 0, stale → 1, missing → 1)
and the ``main(["--check"])`` dispatch are pinned here. These tests redirect
``report_coverage.GOLDEN_PATH`` to a temp file via monkeypatch so the committed
golden is NEVER mutated.

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


class TestCheckGoldenGate:
    """P5e / R17 — pin ``check_golden()`` / ``--check``, the STALENESS GATE that
    ``make cwe-corpus`` runs to fail a PR whose ``VERIFIED_CWES.md`` drifted.

    Every test redirects ``report_coverage.GOLDEN_PATH`` to a ``tmp_path`` file
    so the committed golden is never mutated. ``check_golden()`` is read-only and
    compares ``build_markdown()`` against whatever ``GOLDEN_PATH`` points at, so
    the redirect fully exercises the real gate logic. These assertions FAIL if
    the gate is silently disabled (e.g. ``check_golden`` made to always return 0
    — which would let a stale golden sail through CI undetected).
    """

    def test_check_golden_returns_zero_when_current(self, tmp_path, monkeypatch):
        """A golden that is byte-identical to a fresh regeneration → exit 0."""
        golden = tmp_path / "VERIFIED_CWES.md"
        golden.write_text(report_coverage.build_markdown(), encoding="utf-8")
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.check_golden() == 0

    def test_check_golden_returns_zero_on_trailing_newline_only_diff(
        self, tmp_path, monkeypatch
    ):
        """The gate is robust to an editor's final-newline policy: a golden that
        differs ONLY by trailing newlines still passes (mirrors the T22
        ``_normalize`` rule so the gate and the golden test agree exactly)."""
        golden = tmp_path / "VERIFIED_CWES.md"
        # strip the trailing newline build_markdown() emits → must still pass.
        golden.write_text(
            report_coverage.build_markdown().rstrip("\n"), encoding="utf-8"
        )
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.check_golden() == 0

    def test_check_golden_returns_one_when_stale(self, tmp_path, monkeypatch, capsys):
        """A golden that drifted from the gate result → exit 1 (the whole point
        of the gate). The drift is a content change the ``_normalize`` trailing-
        newline rule can NOT absorb, so it must be reported STALE."""
        golden = tmp_path / "VERIFIED_CWES.md"
        golden.write_text(
            report_coverage.build_markdown() + "\n<!-- hand-edited drift -->\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.check_golden() == 1
        assert "STALE" in capsys.readouterr().out

    def test_check_golden_returns_one_when_missing(self, tmp_path, monkeypatch, capsys):
        """A missing committed golden → exit 1 (a fresh checkout that forgot to
        commit the file must fail CI, not silently pass)."""
        golden = tmp_path / "VERIFIED_CWES.md"  # never created
        assert not golden.exists()
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.check_golden() == 1
        assert "missing" in capsys.readouterr().out.lower()

    def test_check_golden_is_read_only(self, tmp_path, monkeypatch):
        """``--check`` must NEVER write: a stale golden stays byte-for-byte
        unchanged after the check (only ``--write`` mutates the file)."""
        golden = tmp_path / "VERIFIED_CWES.md"
        stale_content = report_coverage.build_markdown() + "\n<!-- drift -->\n"
        golden.write_text(stale_content, encoding="utf-8")
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        report_coverage.check_golden()
        assert golden.read_text(encoding="utf-8") == stale_content

    def test_main_check_dispatches_to_check_golden_current(self, tmp_path, monkeypatch):
        """``main(["--check"])`` returns 0 when the golden is current — the exact
        invocation ``make cwe-corpus`` makes."""
        golden = tmp_path / "VERIFIED_CWES.md"
        golden.write_text(report_coverage.build_markdown(), encoding="utf-8")
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.main(["--check"]) == 0

    def test_main_check_dispatches_to_check_golden_stale(self, tmp_path, monkeypatch):
        """``main(["--check"])`` propagates the nonzero exit on a stale golden so
        the Makefile recipe (and therefore CI) fails."""
        golden = tmp_path / "VERIFIED_CWES.md"
        golden.write_text(
            report_coverage.build_markdown() + "\n<!-- drift -->\n", encoding="utf-8"
        )
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.main(["--check"]) == 1

    def test_main_write_then_check_roundtrips(self, tmp_path, monkeypatch):
        """``main(["--write"])`` writes the golden and a following ``--check``
        passes — proving ``--write`` produces exactly what ``--check`` accepts."""
        golden = tmp_path / "VERIFIED_CWES.md"
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", golden)

        assert report_coverage.main(["--write"]) == 0
        assert golden.is_file()
        assert report_coverage.main(["--check"]) == 0

    def test_committed_golden_passes_check_golden(self, monkeypatch):
        """End-to-end on the REAL committed golden (no redirect): the in-repo
        ``VERIFIED_CWES.md`` is current, so ``check_golden()`` returns 0. This is
        the same assertion ``make cwe-corpus`` relies on, pinned as a test."""
        monkeypatch.setattr(report_coverage, "GOLDEN_PATH", _GOLDEN)
        assert report_coverage.check_golden() == 0
