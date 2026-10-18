"""Feature 0102, A17 (LLD §6.2, §16 risk 15, D5; plan task 2.4): ``FileModel.bytes_estimate``
is the footprint ``from_doc`` actually builds.

The model cache is byte-budgeted by ``bytes_estimate`` (D5). The Phase-1 estimate
(``28 x n`` + text and lit sizes) left out most of what a model holds, so the budget bounded
a number, not memory. A17 makes the estimate the built footprint — array buffers, list
slots, the text and the distinct strings — computed once at build, and pins it: the
``tracemalloc``-measured footprint over ``bytes_estimate`` lies in [0.8, 1.25] on each golden
input and on the calibrated bench tree. The plan names this pin
``test_0102_model_queries.py::test_bytes_estimate_is_the_built_footprint``; it lives in this
module because it needs a measurement harness of its own.

What is measured is what a model KEEPS: everything ``get_model`` does between the worker's
reply and the cached model — decode the reply, validate it, decode the text, build — runs
inside the traced window; then every temporary is released and only the model is alive. A
first, untraced build of the same reply warms any per-process memo, so its growth is not
charged to the model (it is not part of any one model's footprint).

Inputs: the golden inputs of ``test_0102_golden.py`` (nine languages; clean, syntax-error and
hostile; the ``.tsx`` component), each written, read and parsed the production way; and a
256 KB sample of ``tests/perf/gen_tree.py``'s calibrated tree (A6), whose node density is
checked to be within A15's ±10 % of ``gen_tree.DENSITY`` so the sample is the calibrated
shape, not a vacuous one. The ratio over that sample is the sum of footprints over the sum
of estimates, as a cache full of such files would weigh.

A35 (2026-10-17) extends the band to a model's analysis: a model's cache charge covers its
analysis, so ``FlowAnalysis.bytes_estimate`` (computed once, at build) is pinned the same way
on each golden input. What is measured is what the analysis KEEPS as a consumer holds it —
built by ``model.analysis()`` and asked the candidates of every family the model's profile
owns — since that is what the cache's charge must bound for the A5 memory gate to hold by
construction. A first, untraced analysis of the same model warms the per-process memos and
the model's own ``chain_words`` memo (the model's, not the analysis'), then is released.
The charge itself is ``test_0102_cache.py``'s.
"""

from __future__ import annotations

import gc
import json
import tracemalloc
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest

from shared.ast import FileModel
from shared.ast._validate import validate_model
from shared.ast.pool import get_pool
from shared.ast.profile import PROFILES, profile_for
from shared.tools.file_scanner import read_file_safe
from tests.perf import gen_tree
from tests.unit.ast._support import write
from tests.unit.ast.test_0102_golden import CASES, GoldenCase

if TYPE_CHECKING:
    from shared.ast.flow import FlowAnalysis

pytestmark = pytest.mark.usefixtures("real_pool")

_BAND = (0.8, 1.25)  # A17: footprint / bytes_estimate
_SAMPLE_FILES = 50  # gen_tree's per-file size at its full tree: 5 MB over 1,000 files
_SAMPLE_BYTES = 256 * 1024
_DENSITY_TOLERANCE = 0.10  # A15: bench_ast.DENSITY_TOLERANCE


class _Shipped(NamedTuple):
    """What ``get_model`` holds once the worker answered: the reply as JSON and the bytes
    it shipped (the UTF-8 encoding of the text it read)."""

    reply: bytes
    data: bytes


class _Weighed(NamedTuple):
    kept: int  # tracemalloc: bytes the built model keeps
    estimate: int  # its bytes_estimate
    nodes: int  # its node_count


@pytest.fixture(scope="module", autouse=True)
def _frozen_heap() -> Iterator[None]:
    """Every object alive before this module's tests moves to the permanent generation, so
    each ``gc.collect()`` of ``_weighed`` scans only what a weighing made (the warm-up build
    and the temporaries) rather than the whole session's heap. What is freed inside the traced
    window, and so what is measured, is the same."""
    gc.collect()
    gc.freeze()
    yield
    gc.unfreeze()


def _shipped(path: Path) -> _Shipped:
    """``path`` read, encoded and parsed as ``get_model`` does, with the grammar entry point
    of its suffix (``.tsx``)."""
    text, profile = read_file_safe(path), profile_for(path)
    assert text is not None and profile is not None, path
    data = text.encode("utf-8")
    reply = get_pool().parse(profile.language, data, profile.grammar_for(path))
    assert isinstance(reply, dict), f"{path.name}: the worker fell back ({reply!r})"
    return _Shipped(json.dumps(reply).encode("utf-8"), data)


def _build(shipped: _Shipped) -> FileModel:
    """The reply decoded and validated at the boundary, and the model built from the text."""
    return FileModel.from_doc(validate_model(shipped.reply), shipped.data.decode("utf-8"))


@contextmanager
def _tracing() -> Iterator[None]:
    """``tracemalloc`` on for the block (left as it was if something else turned it on)."""
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        yield
    finally:
        if started:
            tracemalloc.stop()


def _weighed(shipped: _Shipped) -> _Weighed:
    """The traced size a second build of ``shipped`` adds and keeps, with only its model
    alive (the first build warms per-process memos outside the window)."""
    _build(shipped)
    gc.collect()
    with _tracing():
        before = tracemalloc.get_traced_memory()[0]
        model = _build(shipped)
        gc.collect()
        kept = tracemalloc.get_traced_memory()[0] - before
    return _Weighed(kept, model.bytes_estimate, model.node_count)


def _ratio(weighed: Sequence[_Weighed]) -> float:
    return sum(w.kept for w in weighed) / sum(w.estimate for w in weighed)


def _density(weighed: Sequence[_Weighed], total_bytes: int) -> float:
    """Model nodes per 10^6 bytes, ``gen_tree.DENSITY``'s unit (A6)."""
    return sum(w.nodes for w in weighed) / total_bytes * 1e6


def _within_band(ratio: float) -> bool:
    return _BAND[0] <= ratio <= _BAND[1]


@pytest.mark.parametrize("case", CASES, ids=lambda case: f"{case.language}/{case.name}")
def test_bytes_estimate_is_the_built_footprint(tmp_path: Path, case: GoldenCase) -> None:
    """A17, each golden input: footprint / ``bytes_estimate`` in [0.8, 1.25]."""
    weighed = _weighed(_shipped(write(tmp_path / case.language / case.name, case.source)))

    ratio = _ratio([weighed])

    assert _within_band(ratio), f"{weighed} -> {ratio:.2f}, outside {_BAND}"


def test_bytes_estimate_is_the_built_footprint_on_the_calibrated_tree(tmp_path: Path) -> None:
    """A17 on a sample of A6's calibrated tree (A15's density check first, so the sample is
    the gating shape): footprint / ``bytes_estimate`` in [0.8, 1.25] over the whole sample."""
    tree = gen_tree.generate(tmp_path / "tree", files=_SAMPLE_FILES, total=_SAMPLE_BYTES)

    weighed = [_weighed(_shipped(path)) for path in tree.paths]

    density = _density(weighed, tree.total_bytes)
    assert abs(density / gen_tree.DENSITY - 1) <= _DENSITY_TOLERANCE, (density, gen_tree.DENSITY)
    ratio = _ratio(weighed)
    assert _within_band(ratio), f"{ratio:.2f} over {len(weighed)} files, outside {_BAND}"


# ── A35: an analysis' estimate is its footprint ──────────────────────────────


def _held(model: FileModel) -> FlowAnalysis:
    """``model.analysis()`` as a consumer holds it: built, then asked the candidates of every
    family the model's profile owns."""
    analysis = model.analysis()
    for family in sorted(PROFILES[model.language].owned_families):
        analysis.candidates(family)
    return analysis


def _analysis_weighed(shipped: _Shipped) -> _Weighed:
    """The traced size a second analysis of ``shipped``'s model adds and keeps, held as
    ``_held`` holds it, with only the model and that analysis alive (the first analysis warms
    the per-process memos and the model's ``chain_words`` memo outside the window, then is
    released)."""
    model = _build(shipped)
    _held(model)
    model.release()
    gc.collect()
    with _tracing():
        before = tracemalloc.get_traced_memory()[0]
        analysis = _held(model)
        gc.collect()
        kept = tracemalloc.get_traced_memory()[0] - before
    return _Weighed(kept, analysis.bytes_estimate, model.node_count)


@pytest.mark.parametrize("case", CASES, ids=lambda case: f"{case.language}/{case.name}")
def test_analysis_bytes_estimate_is_the_held_footprint(tmp_path: Path, case: GoldenCase) -> None:
    """A35, each golden input: the footprint of the model's analysis as a consumer holds it,
    over ``analysis.bytes_estimate``, in [0.8, 1.25]."""
    weighed = _analysis_weighed(_shipped(write(tmp_path / case.language / case.name, case.source)))

    ratio = _ratio([weighed])

    assert _within_band(ratio), f"{weighed} -> {ratio:.2f}, outside {_BAND}"
