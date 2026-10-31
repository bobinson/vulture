"""A temporary directory whose path no skill classifies (feature 0098 tests).

The offline gate, and the full audit it is compared against, classify a file by
every component of its absolute path (``tests/``, ``build/``, ``docs/``, ...).
A fixture derived from pytest's ``--basetemp`` inherits whatever that option
points at, so a run with ``--basetemp=<x>/build/pt`` would change the verdicts
under test. ``neutral_dir`` never derives from the basetemp.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from cwe_agent import offline

_BASES = (tempfile.gettempdir(), "/tmp", "/var/tmp")


def _inside_a_repository(path: Path) -> bool:
    return any((d / ".git").exists() for d in path.parents)


def _acceptable(path: Path) -> bool:
    return offline._is_neutral(path) and not _inside_a_repository(path)


def _make(base: str) -> Path | None:
    if not Path(base).is_dir():
        return None
    path = Path(tempfile.mkdtemp(prefix="vulture-t-", dir=base)).resolve()
    if _acceptable(path):
        return path
    shutil.rmtree(path, ignore_errors=True)
    return None


def neutral_dir(request: pytest.FixtureRequest) -> Path:
    """A new, empty directory under a neutral system temp base, removed after the test."""
    path = next((p for p in map(_make, dict.fromkeys(_BASES)) if p is not None), None)
    if path is None:
        pytest.skip("no neutral temporary base directory on this host")
    request.addfinalizer(lambda: shutil.rmtree(path, ignore_errors=True))
    return path
