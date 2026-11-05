"""Feature 0074 P-1 (T-1.5, AC26') — ``VULTURE_LLM_TRUST_MODEL_CHECK_ID`` is
retired, and the feature adds no environment variable.

CLAUDE.md rule 6 (no new environment flags) and the measured fact behind it:
the switch has NO effect on the final row. With either value the model's
``check_id`` reaches the public row, because ``_restore_dedup_identity`` puts
it back after the parse-time strip. A switch that cannot change the outcome
is not a rollback hatch, it is documentation debt. Retiring it means no
production source reads it and no operator-facing surface (the CLAUDE.md env
list, the compose files, ``env.example``, the install/launch scripts) still
offers it.

The inventory is the repo's tracked + untracked-but-not-ignored file list
(``git ls-files``), so a vendored tree or a virtualenv never counts.
"""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_RETIRED = "VULTURE_LLM_TRUST_MODEL_CHECK_ID"
_SOURCE_SUFFIXES = {".py", ".go", ".ts", ".tsx", ".sh"}
_TEST_DIRS = {"tests", "test", "testdata", "e2e", "__tests__"}
# Operator-facing configuration surfaces at the repo root: each one offers a
# switch to whoever deploys Vulture, so a retired switch must leave all of them.
_OPERATOR_SURFACES = (
    "env.example", "config.ini.example", "install.sh",
    "docker-compose.yml", "docker-compose.readonly.yml",
)
_ENV_NAME = re.compile(r"\bVULTURE_[A-Z0-9_]*[A-Z0-9]\b")


def _git(*args: str) -> str:
    out = subprocess.run(["git", "-C", str(_REPO_ROOT), *args],
                         capture_output=True, text=True, check=False)
    return out.stdout if out.returncode == 0 else ""


def _is_test_path(rel: str) -> bool:
    parts = Path(rel).parts
    return bool(_TEST_DIRS & set(parts)) or re.search(r"(_test\.go|\.(test|spec)\.tsx?)$", rel) is not None


def _is_production_source(rel: str) -> bool:
    return Path(rel).suffix in _SOURCE_SUFFIXES and not _is_test_path(rel)


@lru_cache(maxsize=1)
def _worktree_files() -> tuple[str, ...]:
    """Listed once per session; three tests walk it."""
    return tuple(_git("ls-files", "--cached", "--others", "--exclude-standard").splitlines())


@lru_cache(maxsize=None)
def _text(rel: str) -> str:
    """A repo file's text, read once per session ("" when it is not a file)."""
    path = _REPO_ROOT / rel
    return path.read_text(errors="ignore") if path.is_file() else ""


def _mentions(rel: str, needle: str) -> bool:
    return needle in _text(rel)


def test_no_production_source_reads_the_retired_switch():
    """AC26' / T-1.5: no production source (agents, backend, cli, mcp,
    scripts, frontend) reads or names it. Any mention counts: a production
    file that still spells the name is either reading it or pointing a reader
    at a switch that no longer exists."""
    readers = [r for r in filter(_is_production_source, _worktree_files()) if _mentions(r, _RETIRED)]
    assert readers == [], f"{_RETIRED} is retired (rule 6) but is still read by: {readers}"


def test_claude_md_does_not_document_the_retired_switch():
    """AC26' / T-1.5: the env list in CLAUDE.md no longer offers it to operators."""
    assert _RETIRED not in (_REPO_ROOT / "CLAUDE.md").read_text(), (
        f"CLAUDE.md still documents {_RETIRED}; a retired switch must leave the env list"
    )


@pytest.mark.parametrize("surface", _OPERATOR_SURFACES)
def test_no_operator_surface_offers_the_retired_switch(surface):
    """AC26' / T-1.5: compose files forward env to every agent and env.example
    is what an operator copies; a retired switch must leave both, or operators
    keep being handed a knob that does nothing."""
    assert not _mentions(surface, _RETIRED), (
        f"{surface} still offers the retired {_RETIRED}"
    )


def _base_commit() -> str:
    return _git("merge-base", "HEAD", "main").strip()


def _names_at_base(base: str) -> set[str]:
    out = _git("grep", "-ohE", _ENV_NAME.pattern.replace(r"\b", ""), base, "--")
    return set(out.split())


def _names_now() -> set[str]:
    names: set[str] = set()
    for rel in filter(_is_production_source, _worktree_files()):
        names |= set(_ENV_NAME.findall(_text(rel)))
    return names


def test_feature_introduces_no_new_environment_variable():
    """AC26' (second half, rule 6): every VULTURE_* name production code
    spells today was already spelled somewhere in the repo at the branch base.
    A name this feature invents would show up here. Regression pin: green now
    and must stay green through the green team's work."""
    base = _base_commit()
    if not base:
        pytest.skip("no git merge-base with main; cannot diff the env inventory")
    new = sorted(_names_now() - _names_at_base(base))
    assert new == [], f"feature 0074 must add no environment variable (rule 6); new: {new}"
