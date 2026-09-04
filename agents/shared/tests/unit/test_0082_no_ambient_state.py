"""Feature 0082 C8 — `window.py` must carry no ambient state.

`sse_app` drives eight generators in one interpreter. A module-level mutable,
a ContextVar, or a new `lru_cache` in this module would be cross-audit
contamination — one audit's source window appearing on another audit's finding.
CLAUDE.md records three prior incidents of exactly this shape, which is why the
design explicitly forbade bridging the seam with ambient state.

A new `lru_cache` is separately forbidden because it would be invisible to
`file_scanner.clear_caches()`, which already records two caches omitted before.
"""
import ast
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.tools.window import ensure_code_window

_WINDOW_SRC = Path(__file__).resolve().parents[2] / "shared" / "tools" / "window.py"


def test_module_declares_no_mutable_module_level_state():
    tree = ast.parse(_WINDOW_SRC.read_text())
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if not isinstance(t, ast.Name):
                    continue
                val = node.value
                # A bare list/dict/set literal is mutable state. A frozen
                # container (frozenset(...), MappingProxyType({...})) is a
                # constant and is allowed — the risk is data carried BETWEEN
                # audits, not a read-only lookup table.
                assert not isinstance(val, (ast.List, ast.Dict, ast.Set)), (
                    f"{t.id} is a module-level mutable — cross-audit contamination "
                    f"risk. Wrap it in MappingProxyType/frozenset if it is a constant."
                )


def test_module_introduces_no_cache_and_no_contextvar():
    """Scans the AST, not the text: the module docstring NAMES these as
    forbidden, and a raw grep cannot tell a prohibition from a violation."""
    tree = ast.parse(_WINDOW_SRC.read_text())
    banned = {"lru_cache", "cache", "ContextVar"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            raise AssertionError(f"`global` in window.py: ambient state ({node.names})")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                assert alias.name not in banned, (
                    f"window.py imports {alias.name}: a cache here is invisible to "
                    f"file_scanner.clear_caches(); a ContextVar is ambient state"
                )
        if isinstance(node, ast.Name) and node.id in banned:
            raise AssertionError(f"window.py references {node.id} in code")
        if isinstance(node, ast.Attribute) and node.attr in banned:
            raise AssertionError(f"window.py references .{node.attr} in code")


def test_concurrent_passes_over_two_roots_do_not_cross_contaminate(tmp_path):
    root_a = tmp_path / "a"; root_a.mkdir()
    root_b = tmp_path / "b"; root_b.mkdir()
    (root_a / "shared_name.ts").write_text("\n".join(f"AAA_line_{i}" for i in range(1, 40)) + "\n")
    (root_b / "shared_name.ts").write_text("\n".join(f"BBB_line_{i}" for i in range(1, 40)) + "\n")

    def run(root, tag):
        fs = [{"category": "CWE-79", "file_path": "shared_name.ts",
               "line_start": 20, "title": f"{tag}-{i}"} for i in range(12)]
        ensure_code_window(fs, str(root))
        return tag, fs

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda t: run(*t), [(root_a, "A"), (root_b, "B")] * 4))

    # NON-VACUITY: both roots must actually have produced windows.
    by_tag = {}
    for tag, fs in results:
        by_tag.setdefault(tag, []).extend(fs)
    for tag in ("A", "B"):
        windowed = [f for f in by_tag[tag] if f.get("code_snippet")]
        assert windowed, f"root {tag} produced no windows at all — test proves nothing"

    for f in by_tag["A"]:
        assert "BBB_line" not in f.get("code_snippet", ""), "root B leaked into root A"
    for f in by_tag["B"]:
        assert "AAA_line" not in f.get("code_snippet", ""), "root A leaked into root B"
