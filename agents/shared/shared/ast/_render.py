"""The one renderer of every path the AST layer emits (feature 0102, LLD §10.3, §11 T15, A30).

A scanned repository names its own files, and an adversarial one names them with terminal
control sequences: an ANSI colour, an OSC title, a bell, a newline that would forge a second
``thinking`` line, a bidi override. Every path the layer shows a person — a rendered decline,
the display ``fallback_paths`` — goes through ``safe_path``: root-relative, printable ASCII
only (any other character becomes ``?``), at most the first ``MAX_RENDERED_PATH`` characters.

``relative`` is the LOSSLESS form the same paths take where a program reads them (the D24
``fallback_keys``): the POSIX ``normpath`` of the root-relative path (A31 (3)), never
sanitised, so the lineage guard matches it against the file it names.

This module imports nothing beyond ``limits`` and the standard library.
"""

from __future__ import annotations

import os
import re

from shared.ast.limits import MAX_RENDERED_PATH

__all__ = ["relative", "safe_path", "safe_relative"]

type _PathLike = str | os.PathLike[str]

# Anything outside printable ASCII (space through tilde): C0 and C1 controls, DEL, non-ASCII
# letters, bidi overrides and the lone surrogates of an undecodable file name alike.
_UNPRINTABLE = re.compile(r"[^ -~]")


def relative(root: _PathLike, path: _PathLike) -> str:
    """``path`` relative to ``root``, ``..`` spellings folded (``os.path.relpath`` normalises
    both sides lexically), ``/``-separated: the canonical, lossless key of a file (A31 (3))."""
    return os.path.relpath(path, root).replace(os.sep, "/")


def safe_path(root: _PathLike, path: _PathLike) -> str:
    """§10.3: ``path`` as a person may be shown it — root-relative, its first
    ``MAX_RENDERED_PATH`` characters, each outside printable ASCII shown as ``?``."""
    return safe_relative(relative(root, path))


def safe_relative(rel: str) -> str:
    """``safe_path`` of a path already made root-relative (``relative``): the cut comes first,
    so the substitution reads at most ``MAX_RENDERED_PATH`` characters."""
    return _UNPRINTABLE.sub("?", rel[:MAX_RENDERED_PATH])
