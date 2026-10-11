"""Fixture-marker helper shared by every feature 0101 E2E test (LLD 6.2).

GRAMMAR
    ``EXPECT: finding|clean [check=<check_id>]`` at the END of a site line, or
    ``EXPECT-NEXT: finding|clean [check=<check_id>]`` on its OWN line, asserting
    on the line below it. A same-line ``EXPECT:`` alone on a comment line is a
    fixture bug (it would assert on the comment) and raises.

    Held-out files also declare ``HELD-OUT-TOKENS: a, b, c`` -- the API tokens
    their sites depend on, which no 0101 lexicon may contain (LLD 4.6).

WHY A NEUTRAL COPY
    The three 0101 rules skip test paths (``is_test_file``), so scanning
    ``tests/e2e/fixtures/**`` in place yields zero findings and every ``clean``
    expectation passes vacuously (RC-09). Every 0101 E2E test scans
    ``neutral_copy(...)`` and asserts a population floor, so a run that scans
    nothing fails instead of passing.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from shared.tools.file_scanner import is_test_file

_MARKER = re.compile(r"EXPECT(-NEXT)?:\s*(finding|clean)\b(?:\s+check=([\w.]+))?")
_HELD_OUT = re.compile(r"HELD-OUT-TOKENS:[ \t]*([^\n]+?)[ \t]*(?:\*/|-->)?[ \t]*$", re.MULTILINE)
# A line that STARTS with one of these is a comment line, so a same-line marker
# on it would assert on the comment itself. A code line that happens to start
# with one (`--n;`, `*p = 0;`) is refused loudly, never misread: use EXPECT-NEXT.
_COMMENT_LEADERS = ("#", "//", "/*", "*", "--", ";", "%", "<!--")


@dataclass(frozen=True, order=True)
class Site:
    rel: str            # path relative to the fixture root (posix)
    line: int           # 1-based line the expectation is about
    verdict: str        # "finding" | "clean"
    check: str | None   # optional check_id the verdict is scoped to


def _is_comment_only(prefix: str) -> bool:
    text = prefix.lstrip()
    return not text.strip() or text.startswith(_COMMENT_LEADERS)


def _site_for(match: re.Match[str], lines: list[str], index: int, rel: str) -> Site:
    nxt, verdict, check = match.groups()
    if nxt:
        if index + 1 >= len(lines):
            raise ValueError(f"{rel}:{index + 1}: EXPECT-NEXT on the last line has no site")
        return Site(rel, index + 2, verdict, check)
    if _is_comment_only(lines[index][: match.start()]):
        raise ValueError(f"{rel}:{index + 1}: same-line EXPECT on its own line; use EXPECT-NEXT")
    return Site(rel, index + 1, verdict, check)


def parse_markers(path: Path, root: Path | None = None) -> list[Site]:
    """Every expectation in one fixture file, in line order."""
    rel = path.relative_to(root).as_posix() if root else path.name
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [
        _site_for(m, lines, i, rel)
        for i, line in enumerate(lines)
        if (m := _MARKER.search(line))
    ]


def parse_tree(root: Path) -> list[Site]:
    """Every expectation under ``root``, paths relative to it."""
    return [s for p in _files(root) for s in parse_markers(p, root)]


def held_out_tokens(path: Path) -> tuple[str, ...]:
    """The ``HELD-OUT-TOKENS:`` declaration of a held-out fixture (empty if none)."""
    m = _HELD_OUT.search(path.read_text(encoding="utf-8", errors="replace"))
    return tuple(filter(None, map(str.strip, m.group(1).split(",")))) if m else ()


def neutral_copy(src_dir: Path, tmp_path: Path) -> Path:
    """Copy a fixture tree to ``tmp_path/fixcorpus/app`` and return that root.

    Refuses (AssertionError) an empty copy, and a destination where any copied
    file is still a test path -- the classification the 0101 rules skip on -- so
    the copy can never reproduce the vacuous in-place scan. (The stricter
    whole-audit neutrality of ``offline._is_neutral`` rejects every pytest
    ``tmp_path``, and no 0101 rule reads those other classifiers.)
    """
    root = tmp_path / "fixcorpus" / "app"
    shutil.copytree(src_dir, root)
    files = _files(root)
    classified = sum(map(is_test_file, files))
    assert files and not classified, (
        f"neutral copy at {root} lands on a test path ({classified} of "
        f"{len(files)} files classified as tests); choose another tmp_path"
    )
    return root


def _files(root: Path) -> list[Path]:
    return [p for p in sorted(root.rglob("*")) if p.is_file()]


def _rel_of(finding: dict, root: Path | None) -> str:
    path = Path(str(finding.get("file_path", "")))
    if root is not None and path.is_absolute():
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _matches(rel: str, site: Site, exact: bool) -> bool:
    return rel == site.rel if exact else rel == site.rel or rel.endswith("/" + site.rel)


def _same_row(finding: dict, site: Site, category: str) -> bool:
    """Category, line and (when the site names one) check_id agree."""
    return (finding.get("category") == category
            and int(finding.get("line_start") or 0) == site.line
            and site.check in (None, finding.get("check_id")))


def _hit(finding: dict, site: Site, category: str, root: Path | None) -> bool:
    return _same_row(finding, site, category) and _matches(_rel_of(finding, root), site, root is not None)


def verdicts(findings: list[dict], sites: list[Site], category: str,
             root: Path | None = None) -> dict[Site, str]:
    """Observed verdict per site: ``finding`` when a ``category`` row (scoped to
    the site's check_id when it names one) sits on the site's line, else ``clean``.

    With ``root`` the file path must equal the site's path under it; without,
    a path-boundary suffix match is used.
    """
    return {
        s: "finding" if any(_hit(f, s, category, root) for f in findings) else "clean"
        for s in sites
    }


def mismatches(findings: list[dict], sites: list[Site], category: str,
               root: Path | None = None) -> list[tuple[Site, str, str]]:
    """``(site, expected, observed)`` for every site whose verdict differs."""
    got = verdicts(findings, sites, category, root)
    return [(s, s.verdict, got[s]) for s in sites if got[s] != s.verdict]


def assert_population(sites: list[Site], findings: list[dict], min_finding: int,
                      min_clean: int, min_emitted: int) -> None:
    """Marker counts AND an emitted-findings floor: a run that scans nothing fails."""
    n_finding = [s.verdict for s in sites].count("finding")
    counts = (("finding sites", n_finding, min_finding),
              ("clean sites", len(sites) - n_finding, min_clean),
              ("emitted findings", len(findings), min_emitted))
    short = _shortfalls(counts)
    assert not short, "; ".join(short)


def _shortfalls(counts: tuple[tuple[str, int, int], ...]) -> list[str]:
    """``what < floor`` for every (what, count, floor) below its floor."""
    return [f"{n} {what} < floor {floor}" for what, n, floor in counts if n < floor]
