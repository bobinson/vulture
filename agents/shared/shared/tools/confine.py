"""Source-root confinement helpers for LLM-facing tools (feature 0057 P1c).

The read/list/grep tools attached to the LLM agent take a model-controlled
``path``. A prompt-injected or hallucinating model could point them at
``/etc/passwd`` or ``~/.aws/credentials`` and exfiltrate the contents via a
finding (arbitrary-file-read → exfiltration). These helpers keep every tool
access confined to the audit source tree, symlink-escape safe via
``Path.resolve()``.

Inside the tree the tools see what the audit walk sees, and nothing more:
:func:`scan_refusal` for one path, :func:`admitted_files` for a listing. A
file the scan never opens -- a gitignored ``.env``, a ``.vultureignore``d
recording, ``node_modules`` -- must not reach a provider prompt through a tool
either. Both the generate tools and the L5 judge's tools ask these two
functions, so the tools cannot drift from the walker or from each other.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from shared.tools.file_scanner import (
    SKIP_FILES,
    ignored_by_default,
    tree_files,
    walk_excludes,
    walk_reaches,
)

OUTSIDE = "outside"
EXCLUDED = "excluded"

# What a tool says for an EXCLUDED path. A bare error invites the model to read
# it as "the file is absent", and an absence is the one thing it must not
# conclude.
EXCLUDED_MESSAGE = (
    "Error: path is excluded from this audit by the scanner's skip rules, "
    ".gitignore or .vultureignore — it was never scanned. Do not treat this "
    "as evidence of absence."
)

# The dotenv family by its NAME SHAPE: ``.env``, ``.env.<anything>``
# (``.env.production``, ``.env.local``, ``.env.example``) and ``.envrc``.
_DOTENV_NAME = re.compile(r"\.env(?:rc|\..+)?\Z")


def is_within_root(candidate: str | Path, root: Path) -> bool:
    """True iff ``candidate`` resolves to a path inside ``root`` (resolved).

    ``root`` MUST already be resolved by the caller. Any OS error while
    resolving (broken symlink, permission) is treated as "outside" — fail
    closed.
    """
    try:
        resolved = Path(candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        return resolved == root or resolved.is_relative_to(root)
    except AttributeError:  # pragma: no cover — py<3.9
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            return False


def scan_refusal(candidate: str | Path, root: Path) -> str:
    """``""`` when a tool may open ``candidate``; otherwise why not.

    ``OUTSIDE``: it resolves outside ``root`` (which MUST already be resolved).
    ``EXCLUDED``: the audit's walk of ``root`` never opens it -- a folder the
    default ignore file lists or a VCS store, a `.gitignore` or the root
    `.vultureignore`, the autorun-only restriction inside an editor directory
    -- or its name is one no tool serves (:func:`_withheld_name`). A symlink is
    judged by what it resolves to.
    """
    if not is_within_root(candidate, root):
        return OUTSIDE
    return EXCLUDED if _excluded(Path(candidate).resolve(), root) else ""


def _excluded(resolved: Path, root: Path) -> bool:
    """Whether the walk of ``root`` keeps ``resolved`` out.

    The answer must not depend on whether the path exists, or the error a tool
    returns would tell the model whether a hidden file is there
    (``node_modules/pkg/missing.js`` against ``index.js``): a path that does
    not exist is refused whenever a rule would hide it if it did, and any
    other absent path falls through to the tool's own "not found".
    """
    if resolved == root:
        return False
    if walk_reaches(root, resolved):
        return _withheld_file(resolved)
    return resolved.exists() or _hidden_if_present(resolved, root)


def _withheld_file(path: Path) -> bool:
    return path.is_file() and _withheld_name(path.name)


def _hidden_if_present(resolved: Path, root: Path) -> bool:
    """For a path that does not exist: whether a rule of the walk, or a
    withheld name, would keep it out if it did."""
    return walk_excludes(root, resolved) or _withheld_name(resolved.name)


def _withheld_name(name: str) -> bool:
    """A FILE the walk reaches but no tool hands to a model: a SKIP_FILES name
    the scan never reads, a file named like a skipped directory, or one of the
    dotenv family. A committed `.env` is read by the secret scan, which reports
    it; its values must not reach a provider prompt through a tool. Applied to
    files only: a directory such as `.vscode` stays a scope a tool can list,
    and the walk decides what inside it is admitted."""
    return (name in SKIP_FILES or ignored_by_default(name)
            or _DOTENV_NAME.match(name) is not None)


def admitted_files(source_root: str | Path, under: str = "") -> Iterator[Path]:
    """Every file under the root-relative directory ``under`` that a tool may
    open: walked from the scan ROOT, so the root's ignore files hold below any
    subdirectory, and never a withheld name."""
    return (p for p in tree_files(source_root, under=under) if not _withheld_name(p.name))


def rel_under(path: str | Path, root: Path) -> str:
    """``path`` relative to the resolved ``root``, as ``under`` takes it."""
    return Path(path).resolve().relative_to(root).as_posix()
