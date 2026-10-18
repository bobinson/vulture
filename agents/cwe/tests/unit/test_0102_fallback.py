"""Feature 0102 — a file the AST tier cannot model is scanned as today, and the
coverage says so (LLD invariant 1, D10, §10.2).

Two fallback shapes from the ``ast_v1`` group, scanned by the CWE-22 skill:

* ``cwe_22_17.js`` — a trailing syntax error: the model has an ERROR node, so
  ``owns()`` declines and the regex owner fires (``parse_error``).
* ``cwe_22_18.rb`` — Ruby, a language with no v1 profile: ``get_model``
  declines before any parse and the regex owner fires (``unsupported``).

Both still yield their CWE-22 row, with no ``validation.ast``, and the run's
coverage (the process-default ``AuditContext`` a direct caller runs under, D20)
counts one of each. The fallback buckets are the pool's ``FallbackReason`` set
plus the three reasons decided before a worker is asked (plan task 1.3).

RED until ``shared.ast`` exists; both fixtures are already in ``ast_v1``.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, get_args

import pytest

from cwe_agent.skills.input_validation_check import check_input_validation
from shared.tools.file_scanner import clear_caches
from tests import _ast_v1
from tests._ast_v1 import Finding
from tests._neutral import neutral_dir

PARSE_ERROR = "cwe_22_17.js"
UNSUPPORTED = "cwe_22_18.rb"

# Decided in get_model/owns, never by WorkerPool.parse.
DECIDED_BEFORE_THE_POOL = frozenset({"unsupported", "parse_error", "too_large"})


@dataclass(frozen=True)
class _Run:
    rows: list[Finding]
    files: dict[str, Any]


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """The two fallback fixtures alone under a neutral root: the tallies below
    count exactly one file of each kind."""
    root = neutral_dir(request) / "corpus"
    root.mkdir()
    for name in (PARSE_ERROR, UNSUPPORTED):
        shutil.copyfile(_ast_v1.AST_V1 / name, root / name)
    return root


@cache
def _run(root: Path) -> _Run:
    """The CWE-22 skill alone over ``root``, and the coverage it leaves behind.

    Called from the tests, once per root: the coverage is read from
    ``shared.ast``, which a fixture could not import without erroring.
    """
    from shared.ast import context

    clear_caches()
    rows = _ast_v1.owned(check_input_validation(str(root))["findings"])
    return _Run(rows, context.current().coverage.snapshot(root)["files"])


def _on(rows: list[Finding], name: str) -> list[Finding]:
    return [f for f in rows if Path(f["file_path"]).name == name]


@pytest.mark.parametrize("name", [PARSE_ERROR, UNSUPPORTED])
def test_fallback_file_yields_regex_cwe22_rows(root: Path, name: str) -> None:
    rows = _on(_run(root).rows, name)
    assert {f["category"] for f in rows} == {"CWE-22"}, f"no CWE-22 row on {name}: {rows}"
    assert not _ast_v1.ast_rows(rows), rows


def test_parse_error_is_tallied(root: Path) -> None:
    files = _run(root).files
    assert files["fallback"]["parse_error"] == 1, files


def test_unsupported_is_tallied(root: Path) -> None:
    files = _run(root).files
    assert files["fallback"]["unsupported"] == 1, files


def test_parse_error_file_is_listed(root: Path) -> None:
    """``fallback_paths`` is the human-facing list; ``fallback_keys`` is the
    lossless root-relative set the lineage guard reads (D24)."""
    files = _run(root).files
    assert PARSE_ERROR in files["fallback_paths"], files
    assert PARSE_ERROR in files["fallback_keys"], files


def test_fallback_buckets_are_the_pool_reasons_and_three_more(root: Path) -> None:
    from shared.ast.pool import FallbackReason

    expected = set(get_args(FallbackReason)) | DECIDED_BEFORE_THE_POOL
    assert set(_run(root).files["fallback"]) == expected
