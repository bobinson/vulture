"""Feature 0104 WS-A2 (LLD §4.1, revision 3 W11; A66 (1)): each AST head asks for a file's
group of hint-only rows once per (file, rule), where it builds the file's context.

``input_validation_check`` (CWE-22) and ``injection_check`` (CWE-78) each call
``_ast_head.hint_groups(answer, rule, file_path, excluded)`` once per file they own, however
many lines the file's sink spans cover, never once per line.

RED until A2 lands: neither head calls ``hint_groups`` before it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills import injection_check, input_validation_check
from tests import _ast_v1
from tests._neutral import neutral_dir

HEADS = (input_validation_check, injection_check)
CHECKS = ("cwe.input_validation.path_traversal", "cwe.injection.command")
FILES = ("ledger.py", "albums.py")
# Each file: four rows of each rule, and one call per (file, rule).
ROWS = {check: 4 * len(FILES) for check in CHECKS}
CALLS = {(name, check): 1 for name in FILES for check in CHECKS}
# Four entry functions per family, each a sink call over four lines: 16 span lines a family.
_PAIR = '''

def load_{n}(file_path):
    return open(
        file_path,
        "rb",
    ).read()


def show_{n}(file_name):
    subprocess.run(
        "cat " + file_name,
        shell=True,
    )
'''
SOURCE = "import subprocess\n" + "".join(_PAIR.format(n=n) for n in range(4))


def _counting(module: Any, calls: Counter[tuple[str, str]], spans: list[int]) -> Any:
    """``module.hint_groups``, counting each call by (file, check id) and noting how many span
    lines the file's answer has."""
    original = getattr(module, "hint_groups", None)
    assert original is not None, f"{module.__name__} does not call hint_groups"

    def counted(answer: Any, rule: Any, file_path: Any, *args: Any, **kwargs: Any) -> Any:
        calls[Path(file_path).name, rule.check_id] += 1
        spans.append(len(answer.spans or {}))
        return original(answer, rule, file_path, *args, **kwargs)

    return counted


def _written(request: pytest.FixtureRequest) -> Path:
    """``FILES``, each holding ``SOURCE``, under a neutral root (the skills skip test paths)."""
    root = neutral_dir(request)
    for name in FILES:
        (root / name).write_text(SOURCE, encoding="utf-8")
    return root


def _rows_by_check(root: Path) -> dict[str, int]:
    """How many rows each of ``CHECKS`` the two AST skills emit on ``root``."""
    rows = Counter(row["check_id"] for row in _ast_v1.migrated_rows(root))
    return {check: rows[check] for check in CHECKS}


def test_each_head_asks_once_per_file_and_rule(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _written(request)
    calls: Counter[tuple[str, str]] = Counter()
    spans: list[int] = []
    for module in HEADS:
        monkeypatch.setattr(module, "hint_groups", _counting(module, calls, spans))
    assert (_rows_by_check(root), dict(calls)) == (ROWS, CALLS)
    assert min(spans) >= 16, spans
