"""Feature 0102 — the known false negatives of the ``ast_v1`` corpus group.

``corpus_runner`` scores every non-positive manifest row as a clean twin, so a
known gap listed there would read as a passing negative. A known FN is a
fixture under ``fixtures/ast_v1/`` that is NOT a manifest row, pinned here
with the behaviour ``KnownFn.why`` documents. Only the AST-tier pin imports
``shared.ast``, so it alone is RED until the layer exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import corpus_runner
import pytest

from tests import _ast_v1


def _manifest_file(path: Path) -> str:
    """A fixture's manifest ``file`` value: its path under ``fixtures/``."""
    return path.relative_to(corpus_runner.FIXTURES_DIR).as_posix()


@dataclass(frozen=True)
class KnownFn:
    """A fixture the AST tier owns but cannot see the flaw in."""

    name: str  # basename under fixtures/ast_v1/
    cwe: str  # the CWE the flaw is
    family: str  # the AST sink family that would report it
    why: str

    @property
    def path(self) -> Path:
        return _ast_v1.AST_V1 / self.name

    @property
    def row(self) -> str:
        """The manifest ``file`` value this fixture would have."""
        return _manifest_file(self.path)


KNOWN_FN: tuple[KnownFn, ...] = (
    KnownFn(
        name="cwe_78_c_macro.c",
        cwe="78",
        family="command",
        why="the C preprocessor is not expanded: system() behind #define RUN(x) system(x)",
    ),
    KnownFn(
        name="cwe_78_c_stdin.c",
        cwe="78",
        family="command",
        why="a stdin read through an output buffer is not modelled: fgets(buf, ..., stdin)",
    ),
)

each_gap = pytest.mark.parametrize("gap", KNOWN_FN, ids=[gap.name for gap in KNOWN_FN])


def _scored_rows() -> set[str]:
    return {entry["file"] for entry in _ast_v1.load_group()}


def _known_rows() -> set[str]:
    return {gap.row for gap in KNOWN_FN}


# ── bookkeeping ───────────────────────────────────────────────────────────
def test_known_fns_are_not_scored_rows() -> None:
    scored = _known_rows() & _scored_rows()
    assert not scored, f"scored as clean twins, hiding the gap: {sorted(scored)}"


def test_every_fixture_is_a_scored_row_or_a_known_fn() -> None:
    on_disk = {_manifest_file(p) for p in _ast_v1.AST_V1.iterdir() if p.is_file()}
    accounted = _scored_rows() | _known_rows()
    assert on_disk == accounted, {
        "fixture with no row": sorted(on_disk - accounted),
        "row with no fixture": sorted(accounted - on_disk),
    }


# ── end to end ────────────────────────────────────────────────────────────
@each_gap
def test_deterministic_tiers_report_nothing(gap: KnownFn) -> None:
    fired = corpus_runner.run_deterministic(str(gap.path))
    assert f"CWE-{gap.cwe}" not in fired, (
        f"{gap.name}: CWE-{gap.cwe} now reported - the gap closed; score it as a positive"
    )


# ── the AST tier (RED until shared.ast exists) ────────────────────────────
def _external(flow: Any) -> bool:
    """The flow carries an external origin (LLD D8), the only reportable class."""
    return any(origin.cls == "external" for origin in flow.origins)


def _reaching(model: Any, family: str) -> list[Any]:
    """The candidate sinks of ``family`` that an external origin reaches."""
    return [flow for flow in model.analysis().candidates(family) if _external(flow)]


@each_gap
def test_ast_tier_owns_the_file_but_no_external_origin_reaches_a_sink(gap: KnownFn) -> None:
    from shared.ast import owns

    model = owns(gap.path)
    assert model is not None, f"{gap.name}: not AST-owned, so the gap is not the AST tier's"
    assert not _reaching(model, gap.family), (
        f"{gap.name}: an external origin now reaches a {gap.family} sink ({gap.why})"
        " - re-check the gap"
    )
