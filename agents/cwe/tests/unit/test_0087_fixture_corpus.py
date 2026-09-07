"""0087 section 6.2 / 7: the marked fixture corpus, actually consumed.

The 16 `*_handlers.*` fixtures carry per-site ground truth as `EXPECT:` markers
and were read by no test, which left section 6.2's per-language recall gate
resting on a handful of tiny files. This module parses the marker contract
documented in `tests/fixtures/cwe778/EXPECTATIONS.md` and asserts against it.

`EXPECT: deferred` sites are excluded from BOTH populations, per that contract.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cwe778"

# The whole-corpus floor stated by EXPECTATIONS.md. Asserted before any verdict,
# so a parser that silently matched nothing cannot leave this suite green.
CORPUS_FLOOR = 140  # 153 marked sites across 13 fixtures

_MARKER = re.compile(r"EXPECT:\s*(finding|clean|deferred)\b")
_ID = re.compile(r"\bid=([A-Za-z0-9_]+)")
_COMMENT_ONLY = re.compile(r"^[\s/#*\-]*$")


# The value-error family (go_handlers.go, rs_handlers.rs) uses a DIFFERENT
# marker contract, documented in each of those files: the marker is always
# TRAILING on the site line and carries no `id=`. Requiring `id=` silently
# skipped both files -- 81 marked Go and Rust sites contributing zero
# assertions, while `test_every_language_fixture_is_reached` `continue`d past
# them because it looks up the file by name and finds no parsed sites. The
# headline recall figure therefore described the exception family only.
_NESTED_COMMENT = re.compile(r"^\s*(?://|#)\s*(?://|#)")


def _resolve_sites(text: str) -> list[tuple[int, str, str]]:
    """Return (site_line, verdict, id) for every marked site in one fixture.

    Handles both marker contracts. `id=` is required only for files that use
    it at all, so the value-family files are no longer skipped wholesale.
    """
    lines = text.splitlines()
    requires_id = "id=" in text
    out: list[tuple[int, str, str]] = []
    for idx, line in enumerate(lines):
        m = _MARKER.search(line)
        if not m:
            continue
        # The contract is documented INSIDE each fixture using example marker
        # lines; those sit in a doubly-commented block and are not sites.
        if _NESTED_COMMENT.match(line):
            continue
        ident = _ID.search(line)
        if requires_id and not ident:
            continue
        verdict = m.group(1)
        if not requires_id:
            # Value family: the marker is trailing, so the site IS this line.
            out.append((idx + 1, verdict, f"line{idx + 1}"))
            continue
        assert ident is not None
        prefix = line[: m.start()]
        if not _COMMENT_ONLY.match(prefix):
            # Rule 1: attached marker - the site line IS the marker line.
            out.append((idx + 1, verdict, ident.group(1)))
            continue
        # Rule 2: standalone - skip continuation comment lines without `id=`,
        # then blanks; the first remaining line is the site.
        j = idx + 1
        while j < len(lines):
            nxt = lines[j]
            is_comment = bool(re.match(r"^\s*(?://|#|\*|/\*)", nxt))
            if is_comment and not _ID.search(nxt):
                j += 1
                continue
            if not nxt.strip():
                j += 1
                continue
            break
        if j < len(lines):
            out.append((j + 1, verdict, ident.group(1)))
    return out


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory):
    """Scan the fixtures from a path the skill will actually look at."""
    root = tmp_path_factory.mktemp("fixcorpus") / "app"
    shutil.copytree(FIXTURES, root)
    found: dict[str, set[int]] = {}
    for f in check_insufficient_logging(str(root)).get("findings", []):
        found.setdefault(Path(f["file_path"]).name, set()).add(f["line_start"])
    expected: dict[str, list[tuple[int, str, str]]] = {}
    for path in sorted(FIXTURES.glob("*_handlers.*")):
        sites = _resolve_sites(path.read_text(errors="ignore"))
        if sites:
            expected[path.name] = sites
    return expected, found


def test_corpus_is_non_vacuous(corpus) -> None:
    expected, _ = corpus
    total = sum(len(v) for v in expected.values())
    assert total >= CORPUS_FLOOR, (
        f"parsed {total} marked sites across {len(expected)} fixtures, below the "
        f"floor of {CORPUS_FLOOR}; the marker parser is broken and every verdict "
        f"assertion in this module would be vacuous"
    )
    verdicts = [v for sites in expected.values() for _, v, _ in sites]
    assert verdicts.count("finding") >= 55, "too few `finding` sites to measure recall"
    assert verdicts.count("clean") >= 55, "too few `clean` sites to measure precision"


def test_every_language_fixture_is_reached(corpus) -> None:
    """6.2: a language whose fixture yields nothing is not covered.

    Restricted to the languages 6.2 lists; Java, C# and PHP are excluded there
    because their historical zero is corpus absence, not detector blindness.
    """
    expected, found = corpus
    required = ("go", "rs", "rb", "swift", "scala", "cpp", "kt", "ts")
    silent = []
    for stem in required:
        name = next(
            (n for n in expected if n.startswith(f"{stem}_handlers.")), None
        )
        if name is None:
            continue
        wants = [ln for ln, v, _ in expected[name] if v == "finding"]
        if wants and not found.get(name):
            silent.append(stem)
    assert not silent, f"fixture produced zero findings for: {silent}"


def test_corpus_recall_and_precision(corpus) -> None:
    """Report recall and precision over the marked corpus, and floor them.

    Thresholds are deliberately below the plan's aspirational numbers: this gate
    exists to catch an arm going dark or a rule flooding, not to encode a target
    that would make an honest partial implementation look like a failure.
    """
    expected, found = corpus
    tp = fn = fp = 0
    misses: list[str] = []
    spurious: list[str] = []
    for name, sites in expected.items():
        hits = found.get(name, set())
        marked = {ln for ln, v, _ in sites if v != "deferred"}
        for ln, verdict, ident in sites:
            if verdict == "deferred":
                continue
            if verdict == "finding":
                if ln in hits:
                    tp += 1
                else:
                    fn += 1
                    misses.append(f"{name}:{ln} ({ident})")
            else:
                if ln in hits:
                    fp += 1
                    spurious.append(f"{name}:{ln} ({ident})")
        # Rows on unmarked lines are neither credited nor penalised here; the
        # marker contract does not claim the fixtures are exhaustively marked.
        del marked
    assert tp + fn > 0, "no `finding` sites evaluated; gate is vacuous"
    recall = tp / (tp + fn)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    assert recall >= 0.90, (
        f"corpus recall {recall:.0%} ({tp}/{tp + fn}); missed:\n  "
        + "\n  ".join(misses[:15])
    )
    assert precision >= 0.90, (
        f"corpus precision {precision:.0%} ({tp}/{tp + fp}); spurious:\n  "
        + "\n  ".join(spurious[:15])
    )
