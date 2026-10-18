"""Feature 0102 (A17, A35): what a model, and its analysis, keep — weighed by ``tracemalloc``.

``bench_ast.py``'s footprint child weighs every model of the calibrated tree with these, by the
method ``tests/unit/ast/test_0102_bytes_estimate.py`` pins the two bands with on its own
inputs. A file is read, encoded and parsed as ``get_model`` does, through the layer's public
seams (``WorkerPool.parse``, ``validate_reply``, ``FileModel.from_doc``), never the cache's
privates. Each weighing builds twice: the first build warms the per-process memos outside the
traced window, the second runs inside it with only what it built left alive. An analysis is
weighed as a consumer holds it: built afresh and asked every family's candidates.

Every ``shared`` import is inside a function: the bench child reads its baseline before the
layer is imported.
"""

from __future__ import annotations

import gc
import json
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class _Estimated(Protocol):
    """A model or an analysis: what it says it weighs (A17, A35)."""

    @property
    def bytes_estimate(self) -> int: ...


@dataclass(frozen=True, slots=True)
class Shipped:
    """One file as ``get_model`` ships it: the worker's reply (as JSON, compact while every
    reply of a tree waits to be weighed), the UTF-8 bytes it parsed and what parsed them."""

    reply: bytes
    data: bytes
    profile: Any
    grammar: str


def shipped(path: Path) -> Shipped:
    """``path`` read from disk, encoded and parsed with its suffix's grammar entry point."""
    from shared.ast.pool import get_pool
    from shared.ast.profile import profile_for
    from shared.tools.file_scanner import read_file_uncached

    text, profile = read_file_uncached(path), profile_for(path)
    if text is None or profile is None:
        raise SystemExit(f"weigh: {path} has no text or no profile")
    data, grammar = text.encode("utf-8"), profile.grammar_for(path)
    reply = get_pool().parse(profile.language, data, grammar)
    if not isinstance(reply, dict):
        raise SystemExit(f"weigh: {path} fell back ({reply!r})")
    return Shipped(json.dumps(reply).encode("utf-8"), data, profile, grammar)


def built(reply: Shipped) -> Any:
    """What ``get_model`` does once the worker answered: the reply decoded and checked at the
    boundary and against its request, then the model. The text is decoded here, inside a
    weighing: the model keeps it, so it is part of what a cached model weighs."""
    from shared.ast import FileModel
    from shared.ast._validate import validate_reply

    doc, text = json.loads(reply.reply), reply.data.decode("utf-8")
    return FileModel.from_doc(validate_reply(doc, reply.profile, reply.grammar, reply.data), text)


def held(model: Any) -> Any:
    """``model``'s analysis built afresh (the one it held released) and asked every family's
    candidates, as a consumer holds it (A38)."""
    from shared.ast.profiles import FAMILIES

    model.release()
    analysis = model.analysis()
    for family in FAMILIES:
        analysis.candidates(family)
    return analysis


def weighed(build: Callable[[], _Estimated]) -> tuple[int, int]:
    """The traced bytes a second ``build()`` keeps with only its result alive, and that
    result's ``bytes_estimate``. What the first build left is untraced, so releasing it
    inside the window moves nothing."""
    build()
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        result = build()
        gc.collect()
        kept = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    return kept, result.bytes_estimate
