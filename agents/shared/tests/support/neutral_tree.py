"""Feature 0076 T5.4 — the Tier M neutral **whole-tree** copier.

Why this exists
---------------
``is_test_file`` / ``is_skill_source_file`` / ``is_generated_file`` reject any
path carrying a ``test`` / ``tests`` / ``skills`` / ``fixtures`` part, and
``audit_runner._llm_eligible_files`` applies the first and third of them to
both feed paths. A planted-defect corpus lives, unavoidably, under
``tests/corpus/fixtures/`` — so scanned where it lives it renders **zero**
files into the LLM prompt. Not "fewer": zero. Any anchor-accuracy number
measured in place would be measured over an empty prompt.

The CWE corpus runner (``agents/cwe/tests/corpus/corpus_runner.py``) already
hits this and works around it by copying each fixture **alone** into a fresh
``mkdtemp()`` under the token-free basename ``f.<ext>``. That is sound for a
regex tier, which reads one file at a time. It is *not* sound for Tier M: the
LLM prompt is built per batch and the thing being measured — where the model
says a defect is — depends on in-file and cross-file context. Flattening
deletes exactly that context; the CWE manifest already records CWE-219 as a
casualty of it.

Hence: whole tree, every path part renamed token-free, **layout preserved**.

What "neutral" means here, precisely
------------------------------------
Every directory becomes ``d<i>`` and every file ``f<i><ext>``, indexed by
sorted position **within its own parent**. That is token-free *by
construction* rather than by blacklist, and it preserves the three properties
the measurement depends on:

* **depth** — a file three directories down stays three directories down;
* **sibling grouping** — files that shared a parent still share one;
* **directory identity** — two distinct source directories never merge.

Bytes are never rewritten, so a manifest ``line`` number still addresses the
same source line after the copy — which is the whole point, since Tier M
scores ``anchor-exact`` / ``anchor-within-window`` / ``anchor-wrong`` against
that number.

Renaming is not universally the safe move
-----------------------------------------
``SKIP_DIRS`` mixes two unrelated kinds of directory:

* trees that are *never* corpus content (``.git``, ``node_modules``,
  ``dist``, ``.venv``…). Renaming ``node_modules`` to ``d0`` would **grant**
  a vendored tree eligibility it never had. These are pruned at the source
  and recorded in :attr:`NeutralTree.pruned`.
* directories a corpus legitimately uses to *organise itself*
  (``fixtures``, ``testdata``, ``data``, ``mocks``, ``snapshots``). Skipping
  these is the defect being routed around, so they are renamed through.

The split is **derived** from ``SKIP_DIRS`` (``PRUNE_DIRS = SKIP_DIRS -
ORGANISATIONAL_DIRS``), not hand-typed, so a future ``SKIP_DIRS`` entry
defaults to *pruned* rather than to silently-eligible.

Probe hygiene (0076): this module never calls a model, never opens a socket,
and never writes to the tree it is given — it only reads from it.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from shared.tools.file_scanner import (
    SKIP_DIRS,
    SKIP_FILES,
    WELL_KNOWN_FILENAMES,
    _is_backup_dir,
    clear_caches,
    effective_suffix,
    is_backup_name,
    is_generated_file,
    is_skill_source_file,
    is_test_file,
)

__all__ = [
    "ORGANISATIONAL_DIRS",
    "PRUNE_DIRS",
    "NeutralTree",
    "copy_tree_neutral",
    "neutral_tree",
    "neutral_violations",
]

NEUTRAL_DIR_PREFIX = "d"
NEUTRAL_FILE_PREFIX = "f"
_TMP_PREFIX = "ntree_"

#: ``SKIP_DIRS`` entries a corpus legitimately uses to organise itself. The
#: scanner skipping these IS the defect T5.4 routes around, so they are
#: renamed through rather than dropped.
ORGANISATIONAL_DIRS = frozenset({
    "data", "fixtures", "testdata", "test-fixtures",
    "snapshots", "__snapshots__", "mocks",
})

#: Never corpus content. Pruned at the SOURCE — renaming these would hand the
#: model a vendored/VCS/build tree dressed as a fixture.
PRUNE_DIRS = SKIP_DIRS - ORGANISATIONAL_DIRS


def neutral_violations(path: Path) -> tuple[str, ...]:
    """Names of the scanner filters ``path`` still trips, in evaluation order.

    Deliberately delegates to the scanner's own predicates rather than
    re-testing the token sets: a copy is "neutral" precisely when the code
    that would exclude it says it would not.
    """
    checks = (
        ("test_file", is_test_file),
        ("skill_source_file", is_skill_source_file),
        ("generated_file", is_generated_file),
    )
    return tuple(label for label, predicate in checks if predicate(path))


@dataclass
class _Accumulator:
    """Mutable state threaded through the recursive walk."""

    to_original: dict[str, str] = field(default_factory=dict)
    to_neutral: dict[str, str] = field(default_factory=dict)
    pruned: list[str] = field(default_factory=list)

    def record(self, original_rel: str, neutral_rel: str) -> None:
        self.to_original[neutral_rel] = original_rel
        self.to_neutral[original_rel] = neutral_rel


@dataclass(frozen=True)
class NeutralTree:
    """The result of a neutral whole-tree copy.

    Attributes:
        root: Root of the copy. Every path under it is token-free.
        to_original: neutral relpath -> original relpath (POSIX, root-relative).
        to_neutral: the inverse mapping.
        pruned: original relpaths dropped rather than renamed, sorted.
    """

    root: Path
    to_original: Mapping[str, str]
    to_neutral: Mapping[str, str]
    pruned: tuple[str, ...]

    def original_of(self, neutral_rel: str) -> str | None:
        """Original relpath for a path in the copy, or None if unknown."""
        return self.to_original.get(neutral_rel)

    def neutral_of(self, original_rel: str) -> str | None:
        """Relpath in the copy for a source file, or None if it was pruned."""
        return self.to_neutral.get(original_rel)


def _neutral_file_name(index: int, name: str) -> str:
    """Token-free basename for the ``index``-th file of a directory.

    ``effective_suffix`` is used rather than ``Path.suffix`` so a shadow copy
    keeps the type the scanner actually classifies it as (``notes.md.bak`` is
    a ``.md``), and the backup marker is re-appended so
    :func:`shared.tools.file_scanner.scan_backup_files` still sees one.

    Canonical extensionless files keep their name: ``Dockerfile`` is already
    token-free, and its *name* is the only reason the scanner reaches it —
    renaming it to ``f0`` would silently drop it from the corpus.
    """
    if name in WELL_KNOWN_FILENAMES:
        return name
    marker = ".bak" if is_backup_name(name) else ""
    return f"{NEUTRAL_FILE_PREFIX}{index}{effective_suffix(name)}{marker}"


def _prunable_dir(name: str) -> bool:
    return name in PRUNE_DIRS or _is_backup_dir(name)


def _prunable(entry: Path) -> bool:
    """True for entries dropped at the source instead of renamed.

    Symlinks go too: a link is not content, and following one can leave the
    tree entirely or loop (the scanner's own walk skips them for the same
    reason).
    """
    if entry.is_symlink():
        return True
    if entry.is_dir():
        return _prunable_dir(entry.name)
    return not entry.is_file() or entry.name in SKIP_FILES


def _classify(
    entry: Path,
    rel_src: PurePosixPath,
    dirs: list[Path],
    files: list[Path],
    acc: _Accumulator,
) -> None:
    if _prunable(entry):
        acc.pruned.append((rel_src / entry.name).as_posix())
    elif entry.is_dir():
        dirs.append(entry)
    else:
        files.append(entry)


def _partition(
    src_dir: Path, rel_src: PurePosixPath, acc: _Accumulator
) -> tuple[list[Path], list[Path]]:
    """Sorted (dirs, files) for one directory; pruned entries recorded."""
    dirs: list[Path] = []
    files: list[Path] = []
    for entry in sorted(src_dir.iterdir()):
        _classify(entry, rel_src, dirs, files, acc)
    return dirs, files


def _copy_file(
    entry: Path,
    dst_dir: Path,
    rel_src: PurePosixPath,
    rel_dst: PurePosixPath,
    index: int,
    acc: _Accumulator,
) -> None:
    name = _neutral_file_name(index, entry.name)
    shutil.copyfile(entry, dst_dir / name)
    acc.record((rel_src / entry.name).as_posix(), (rel_dst / name).as_posix())


def _copy_dir(
    src_dir: Path,
    dst_dir: Path,
    rel_src: PurePosixPath,
    rel_dst: PurePosixPath,
    acc: _Accumulator,
) -> None:
    """Copy one directory's contents, then recurse — layout preserved."""
    dirs, files = _partition(src_dir, rel_src, acc)
    for index, entry in enumerate(files):
        _copy_file(entry, dst_dir, rel_src, rel_dst, index, acc)
    for index, entry in enumerate(dirs):
        child_name = f"{NEUTRAL_DIR_PREFIX}{index}"
        child_dst = dst_dir / child_name
        child_dst.mkdir(exist_ok=True)
        _copy_dir(
            entry, child_dst, rel_src / entry.name, rel_dst / child_name, acc
        )


def copy_tree_neutral(src: str | Path, dest: str | Path) -> NeutralTree:
    """Copy the tree at ``src`` to ``dest``, every path part token-free.

    Deterministic: the same source produces the same names, so a Tier M run is
    re-runnable against a stable mapping.

    Args:
        src: Root of the corpus to copy. Read only; never modified.
        dest: Destination root. Created if absent.

    Returns:
        A :class:`NeutralTree` carrying the copy root and both mappings.
    """
    src_root = Path(src).resolve(strict=True)
    dst_root = Path(dest)
    dst_root.mkdir(parents=True, exist_ok=True)

    acc = _Accumulator()
    root_rel = PurePosixPath(".")
    _copy_dir(src_root, dst_root, root_rel, root_rel, acc)

    # The scanner keys several lru_caches on path strings. Neutral roots are
    # unique per copy, but clear anyway so no stale classification leaks in.
    clear_caches()
    return NeutralTree(
        root=dst_root,
        to_original=dict(acc.to_original),
        to_neutral=dict(acc.to_neutral),
        pruned=tuple(sorted(acc.pruned)),
    )


@contextmanager
def neutral_tree(src: str | Path) -> Iterator[NeutralTree]:
    """Neutral whole-tree copy in a temp dir, removed on exit.

    The temp prefix is itself token-free, and ``mkdtemp``'s random component
    can only ever be compared for *exact* equality against the scanner's
    directory token sets, so it cannot reintroduce a token.
    """
    tmp = tempfile.mkdtemp(prefix=_TMP_PREFIX)
    try:
        yield copy_tree_neutral(src, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        clear_caches()
