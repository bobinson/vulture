"""Feature 0102 (D1): ``import shared.ast`` is a leaf import.

The AST layer runs inside every agent process, and its parent side does no
parsing: tree-sitter is imported only inside the spawned worker. Its public
``__init__`` is lazy, so importing the package must not drag in the validation
phase, the audit runner, the LLM client, the agents SDK or tree-sitter itself.
A layer that pulled any of them in would make every consumer pay their import
cost and, for ``tree_sitter``, would load the native grammar code into the
agent process the worker boundary exists to keep it out of.

The probe runs in a FRESH interpreter: inside pytest these modules are already
in ``sys.modules`` (the isolation fixture imports ``shared.validate`` and
``shared.audit_runner``), so an in-process check would pass or fail on test
order rather than on the import graph.
"""

from __future__ import annotations

import pytest

from tests.support.fresh_import import loaded_after_import

_FORBIDDEN = ("shared.validate", "shared.audit_runner", "litellm", "agents", "tree_sitter")


# The package itself, and the two parent-side modules every ``owns``/``get_model`` call loads
# (through ``shared.tools.file_scanner`` and ``shared.tools.membudget``: the ``shared.tools``
# package must not load its LLM tool wrappers to reach them).
@pytest.mark.parametrize("module", ["shared.ast", "shared.ast.cache", "shared.ast.pool"])
def test_import_leaves_heavy_modules_unloaded(module: str) -> None:
    """A fresh ``import`` of the layer loads none of the five forbidden modules."""
    loaded = loaded_after_import(module, _FORBIDDEN)

    assert loaded == [], (
        f"importing {module} loaded {loaded}; the layer must stay a leaf "
        "(D1: no shared.validate, shared.audit_runner, litellm, agents or "
        "tree_sitter in the parent)"
    )
