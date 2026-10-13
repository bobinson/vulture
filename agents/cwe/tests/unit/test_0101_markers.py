"""Feature 0101 Phase 1 -- self-test of the fixture-marker helper (`tests/e2e/_0101_markers.py`).

Every 0101 E2E test reads its expectations through this helper, so a parsing
slip here would silently turn every per-site assertion into a no-op. The cases
below pin the grammar (LLD 6.2), the neutral copy (the rules skip test paths,
RC-09) and the population floor (a run that scans nothing must fail).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools.file_scanner import is_test_file
from tests.e2e._0101_markers import (
    Site,
    assert_population,
    held_out_tokens,
    mismatches,
    neutral_copy,
    parse_markers,
    parse_tree,
    verdicts,
)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestParseMarkers:
    def test_trailing_and_next_line_markers(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "a.ts", "\n".join([
            "const a = 1;",
            "risky(); // EXPECT: finding",
            "// EXPECT-NEXT: clean check=cwe.insufficient_logging.cwe_778",
            "safe();",
            "other(); # EXPECT: clean",
        ]) + "\n")
        sites = parse_markers(path)
        assert sites == [
            Site("a.ts", 2, "finding", None),
            Site("a.ts", 4, "clean", "cwe.insufficient_logging.cwe_778"),
            Site("a.ts", 5, "clean", None),
        ]

    def test_rel_is_relative_to_root(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "pos/p01.py", "x = 1  # EXPECT: finding\n")
        assert parse_markers(path, tmp_path) == [Site("pos/p01.py", 1, "finding", None)]

    def test_next_marker_on_the_last_line_is_an_error(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "b.py", "x = 1\n# EXPECT-NEXT: finding\n")
        with pytest.raises(ValueError, match="EXPECT-NEXT"):
            parse_markers(path)

    def test_same_line_marker_alone_on_its_line_is_an_error(self, tmp_path: Path) -> None:
        # `EXPECT:` alone would assert on the comment line itself.
        path = _write(tmp_path, "c.rb", "# EXPECT: finding\nrisky\n")
        with pytest.raises(ValueError, match="own line"):
            parse_markers(path)

    def test_text_without_a_verdict_is_not_a_marker(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "d.go", "// EXPECT: maybe\nfoo()\n")
        assert parse_markers(path) == []

    def test_parse_tree_collects_every_file(self, tmp_path: Path) -> None:
        _write(tmp_path, "x/a.py", "a()  # EXPECT: finding\n")
        _write(tmp_path, "y/b.ts", "b(); // EXPECT: clean\n")
        _write(tmp_path, "README.md", "no markers here\n")
        assert sorted(parse_tree(tmp_path)) == [
            Site("x/a.py", 1, "finding", None),
            Site("y/b.ts", 1, "clean", None),
        ]


class TestNeutralCopy:
    def test_copy_lands_on_a_path_no_rule_skips(self, tmp_path: Path) -> None:
        src = tmp_path / "tests" / "e2e" / "fixtures" / "0101_demo"
        _write(src, "sub/handler.ts", "x();\n")
        root = neutral_copy(src, tmp_path / "work")
        copied = root / "sub" / "handler.ts"
        assert copied.read_text() == "x();\n"
        assert root.parts[-2:] == ("fixcorpus", "app")
        assert is_test_file(src / "sub" / "handler.ts")
        assert not is_test_file(copied)

    def test_a_destination_the_scanner_would_skip_is_refused(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        _write(src, "a.py", "x = 1\n")
        with pytest.raises(AssertionError, match="test path"):
            neutral_copy(src, tmp_path / "tests")


class TestPopulationAndVerdicts:
    SITES = [
        Site("a.ts", 2, "finding", None),
        Site("a.ts", 4, "clean", None),
        Site("b.ts", 1, "finding", "cwe.x.one"),
    ]

    @staticmethod
    def _finding(path: str, line: int, cat: str = "CWE-778", check: str = "cwe.x.one") -> dict:
        return {"file_path": path, "line_start": line, "category": cat, "check_id": check}

    def test_verdicts_by_category_and_check(self, tmp_path: Path) -> None:
        root = tmp_path / "fixcorpus" / "app"
        findings = [
            self._finding(str(root / "a.ts"), 2),
            self._finding(str(root / "a.ts"), 4, cat="CWE-209"),
            self._finding(str(root / "b.ts"), 1, check="cwe.x.other"),
        ]
        got = verdicts(findings, self.SITES, "CWE-778", root)
        assert got == {self.SITES[0]: "finding", self.SITES[1]: "clean", self.SITES[2]: "clean"}
        assert mismatches(findings, self.SITES, "CWE-778", root) == [(self.SITES[2], "finding", "clean")]

    def test_verdicts_without_root_match_on_the_path_suffix(self) -> None:
        findings = [self._finding("/x/fixcorpus/app/a.ts", 2), self._finding("/x/app/ba.ts", 4)]
        got = verdicts(findings, self.SITES[:2], "CWE-778")
        assert got == {self.SITES[0]: "finding", self.SITES[1]: "clean"}

    def test_population_floor_passes(self) -> None:
        findings = [self._finding("a.ts", 2), self._finding("b.ts", 1)]
        assert_population(self.SITES, findings, min_finding=2, min_clean=1, min_emitted=2)

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"min_finding": 3, "min_clean": 1, "min_emitted": 0}, "finding sites"),
            ({"min_finding": 0, "min_clean": 2, "min_emitted": 0}, "clean sites"),
            ({"min_finding": 0, "min_clean": 0, "min_emitted": 3}, "emitted"),
        ],
    )
    def test_population_floor_fails(self, kwargs: dict, match: str) -> None:
        findings = [self._finding("a.ts", 2), self._finding("b.ts", 1)]
        with pytest.raises(AssertionError, match=match):
            assert_population(self.SITES, findings, **kwargs)


class TestHeldOutTokens:
    def test_declared_tokens(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "h.ex", "# HELD-OUT-TOKENS: Stream.unfold, :gen_tcp , recv\nx\n")
        assert held_out_tokens(path) == ("Stream.unfold", ":gen_tcp", "recv")

    def test_no_declaration(self, tmp_path: Path) -> None:
        assert held_out_tokens(_write(tmp_path, "h.pl", "print 1;\n")) == ()
