"""Feature 0102 — the per-family consumer heads (LLD §9.2, §9.3) as the skill tests read them.

One home for the steps ``test_0102_path_family_ast``, ``test_0102_ssrf_ast`` and
``test_0102_command_ast`` repeat beside ``_ast_v1.stage`` (named fixtures under a neutral
root): stage one unparseable copy, run ONE skill over the root in an audit of its own, keep
that audit's declines, pick one file's rows of one check id, read an unparseable copy's rows
beside its snapshot, and record which files reach a skill's renamed ``_regex`` body — the
per-file fallback the parse outcome alone selects (D10, D12).
Not a test module: the suites import it as ``from tests import _ast_heads``.

Every import of ``shared.ast`` is function-local and reached only from a test body, as in
``_ast_v1``: a missing consumer then fails a named test instead of erroring a fixture.
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from functools import cache
from operator import itemgetter
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

import pytest

from shared.tools.file_scanner import clear_caches
from tests import _ast_v1
from tests._ast_v1 import Finding

Skill = Callable[[str], dict[str, Any]]

PATH_ID, SSRF_ID, COMMAND_ID = _ast_v1.OWNED_CHECK_IDS

# The subdirectory an unparseable copy is staged under: the copy keeps its basename, so its
# rows read like the snapshot fixture it comes from, apart from the AST-owned files beside it.
UNPARSED = "unparsed"


class Scan(NamedTuple):
    rows: list[Finding]  # every row the skill emitted
    declines: list[str]  # the audit's §10.3 ``ast_decline`` lines, files root-relative


# ── staging ─────────────────────────────────────────────────────────────────
def unparsed(name: str) -> str:
    """The root-relative path ``stage_unparseable`` gives a copy of the file ``name``."""
    return f"{UNPARSED}/{name}"


def stage_unparseable(root: Path, src: Path) -> None:
    """``src`` with ``_ast_v1.UNPARSEABLE`` appended, at ``unparsed(src.name)`` under ``root``:
    an ERROR node in every v1 grammar, so ``owns()`` declines it, and no line moves."""
    target = root / unparsed(src.name)
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(src.read_bytes() + _ast_v1.UNPARSEABLE.encode())


def relative(root: Path, path: str | Path) -> str:
    """``path`` relative to ``root``, ``/``-separated: how a row's file is named here."""
    return Path(path).relative_to(root).as_posix()


# ── one skill, one audit ────────────────────────────────────────────────────
@cache
def scan(skill: Skill, root: Path) -> Scan:
    """``_fresh(skill, root)`` once: the tests of a module read one audit."""
    return _fresh(skill, root)


def _fresh(skill: Skill, root: Path) -> Scan:
    """``skill`` over ``root``, in an audit of its own (D20) entered in a copied context, as
    the runner submits a skill (plan 3.4): its declines are this scan's alone, whatever
    another test entered in this thread. Every call is a new audit."""
    return contextvars.copy_context().run(_audited, skill, root)


def _audited(skill: Skill, root: Path) -> Scan:
    from shared.ast import context

    clear_caches()
    context.enter(root)
    rows = skill(str(root))["findings"]
    return Scan(rows, context.current().ledger.render(root))


def on(run: Scan, root: Path, rel: str, check_id: str) -> list[Finding]:
    """The ``check_id`` rows of ``run`` on the file ``rel``."""
    return [f for f in _ast_v1.rows_for(run.rows, check_id) if relative(root, f["file_path"]) == rel]


def rows_at(run: Scan, root: Path, rel: str, check_id: str) -> list[tuple[int, str | None]]:
    """``(line_start, engine)`` of each ``check_id`` row on ``rel``, by line; the engine as
    ``_ast_v1.engine_of`` names it (``"ast"``, or ``"regex"`` for a row with no
    ``validation.ast``, D13)."""
    found = ((f["line_start"], _ast_v1.engine_of(f)) for f in on(run, root, rel, check_id))
    return sorted(found, key=itemgetter(0))


def declines_on(run: Scan, rel: str) -> list[str]:
    """The decline lines of ``run`` that name the file ``rel`` (§10.3 ``file=<safe_path>``)."""
    return [line for line in run.declines if f" file={rel} " in line]


def snapshot_rows(group: str, name: str) -> list[dict[str, Any]]:
    """The pre-0102 regex snapshot rows of the fixture ``<group>/<name>``."""
    key = _ast_v1.fixture_key(group, name)
    return [row for row in _ast_v1.load_snapshot(group) if row["fixture"] == key]


def fallback_rows(
    run: Scan, root: Path, group: str, name: str, check_id: str
) -> tuple[list[dict[str, Any]], list[Finding]]:
    """The snapshot rows of the fixture ``<group>/<name>``, and ``run``'s ``check_id`` rows on
    its unparseable copy (``stage_unparseable``): what the fallback must reproduce, and what
    it emitted."""
    return snapshot_rows(group, name), on(run, root, unparsed(name), check_id)


# ── which files reach the fallback body ─────────────────────────────────────
def reaching(
    skill: Skill, root: Path, module: ModuleType, body: str, file_of: Callable[[Any], Any]
) -> set[str]:
    """The files (root-relative) for which ``skill`` over ``root`` calls ``module.<body>``,
    a skill's former check body renamed ``_regex`` (LLD §9.2, §9.3), which still runs.

    The head reaches the body by its module global name at call time (§9.2's code), so the
    spy wraps that name; before the head lands the body has its old name and this raises
    ``AttributeError``. ``file_of`` maps the body's first argument to its file: the caller
    knows that argument (input_validation's ``_FileCtx``, injection's ``file_path``). The run
    is a fresh audit, never ``scan``'s cached one, so the spy sees a real run.
    """
    reached: set[str] = set()
    real = getattr(module, body)

    def spy(first: Any, *args: Any, **kwargs: Any) -> Any:
        reached.add(relative(root, file_of(first)))
        return real(first, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module, body, spy)
        _fresh(skill, root)
    return reached
