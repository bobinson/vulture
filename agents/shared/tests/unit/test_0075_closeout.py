"""0075 close-out — T2.8 feed-unify hatch, T3.5/T3.5b header-labelled elision.

T3.5 exists because a bare `...` between two numbered windows tells the model that
something was cut but not WHAT, so it cannot reason about whether the construct it
wants is in the elided region. Naming the omitted ranges in the header costs one
line per file and makes the gap explicit.

T3.5b is the guard that stops this from silently breaking the pipeline: the block
header is PARSED in two places (`_FILE_BLOCK_HEADER_RE` and the `"\\n\\n--- "`
splitter used by the probe), and the elision marker is the exact string
`numbered_line_fraction` skips. Change either and the coverage metric or the batch
segmentation breaks quietly.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from shared.audit_runner import _FILE_BLOCK_HEADER_RE, _format_file_block


def _big(n: int = 120) -> tuple[Path, Path]:
    d = Path(tempfile.mkdtemp())
    p = d / "x.ts"
    p.write_text("\n".join(f"line{i}" for i in range(1, n + 1)) + "\n")
    return d, p


def _two_window_findings(p: Path) -> dict:
    return {str(p): [
        {"file_path": str(p), "line_start": 20, "line_end": 20},
        {"file_path": str(p), "line_start": 100, "line_end": 100},
    ]}


# ── T3.5 — the header names what was cut ────────────────────────────────────

def test_header_names_the_omitted_ranges():
    d, p = _big()
    _rel, text = _format_file_block(p, str(d), _two_window_findings(p))
    header = text.split("\n", 1)[0]
    assert "omitted" in header, f"header must name the elided ranges; got {header!r}"
    # the ranges must be real: between the two windows, 31..89 is gone
    assert re.search(r"lines [\d, \-]+ omitted", header), f"malformed header {header!r}"


def test_header_has_no_suffix_when_nothing_was_omitted():
    """A whole-file render must not claim an elision it did not make."""
    d, p = _big(12)
    _rel, text = _format_file_block(p, str(d), {})
    header = text.split("\n", 1)[0]
    assert "omitted" not in header, f"no elision happened; got {header!r}"


# ── T3.5b — the guard: parsers and the coverage metric must survive ─────────

def test_suffixed_header_still_matches_the_block_regex():
    d, p = _big()
    _rel, text = _format_file_block(p, str(d), _two_window_findings(p))
    header = text.split("\n", 1)[0]
    assert _FILE_BLOCK_HEADER_RE.match(header), (
        f"_FILE_BLOCK_HEADER_RE no longer matches the header — batch segmentation "
        f"breaks silently. header={header!r}"
    )


def test_suffixed_header_still_splits_as_one_block():
    """The probe segments on `\\n\\n--- `; a suffix must not create a second block."""
    d, p = _big()
    _rel, text = _format_file_block(p, str(d), _two_window_findings(p))
    assert len(text.split("\n\n--- ")) == 1, "one file must remain one block"


def test_elision_marker_stays_exactly_three_dots():
    """`numbered_line_fraction` skips a line whose stripped form is exactly `...`.
    Labelling the marker itself (rather than the header) would have made every
    elided file look partially unnumbered — which is why the label goes in the
    header."""
    d, p = _big()
    _rel, text = _format_file_block(p, str(d), _two_window_findings(p))
    markers = [ln for ln in text.split("\n") if ln.strip().startswith("...")]
    assert markers, "expected an elision marker between the two windows"
    for m in markers:
        assert m.strip() == "...", f"marker must stay exactly '...'; got {m!r}"


def test_numbered_fraction_is_still_one_after_labelling():
    d, p = _big()
    _rel, text = _format_file_block(p, str(d), _two_window_findings(p))
    content = [ln for ln in text.split("\n")
               if ln.strip() and not ln.startswith("--- ") and ln.strip() != "..."]
    assert content, "expected rendered content"
    unnumbered = [ln for ln in content if not re.match(r"^\d+: ", ln)]
    assert not unnumbered, f"labelling broke the numbering invariant: {unnumbered[:3]}"


# ── T2.8 — the feed-unify hatch ────────────────────────────────────────────

def test_feed_unify_off_restores_the_pre_0075_divergent_pair(monkeypatch):
    """`VULTURE_LLM_FEED_UNIFY=false` is the one-release escape hatch for the RC3
    fix. It restores the ORIGINAL asymmetry deliberately: the single-shot path back
    to the narrow code-only set, the sweep back to the wide default. That pair is a
    defect, which is why the hatch defaults to unified."""
    from shared.tools.file_scanner import CODE_EXTENSIONS, llm_feed_extensions

    monkeypatch.setenv("VULTURE_LLM_FEED_UNIFY", "false")
    assert llm_feed_extensions(single_shot=True) == CODE_EXTENSIONS, (
        "with unify off the single-shot path must resolve the narrow code set"
    )
    assert llm_feed_extensions(single_shot=False) is None, (
        "with unify off the sweep must pass no extensions= (the wide default)"
    )


def test_feed_unify_on_by_default_gives_both_paths_one_set():
    from shared.tools.file_scanner import llm_feed_extensions

    a = llm_feed_extensions(single_shot=True)
    b = llm_feed_extensions(single_shot=False)
    assert a == b, "unified by default: both paths resolve the same set"
    assert isinstance(a, frozenset), "must stay hashable for the lru_cache key"
