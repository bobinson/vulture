"""AST parser tool for agents."""

import ast
from pathlib import Path
from typing import Any

from agents import function_tool


def parse_ast(path: str) -> dict:
    """Parse a source file and return its AST summary.

    Detects language from file extension and extracts structural info
    (functions, classes, imports).

    Args:
        path: Path to source file.

    Returns:
        Dict with language, functions, classes, imports.
    """
    file_path = Path(path)
    ext = file_path.suffix.lower()

    if ext == ".py":
        return _parse_python(file_path)

    return {"language": "unknown", "functions": [], "classes": [], "imports": []}


def _parse_python(file_path: Path) -> dict[str, Any]:
    """Parse a Python file's AST."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        return {"language": "python", "functions": [], "classes": [], "imports": [], "error": True}

    functions: list[dict] = []
    classes: list[dict] = []
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append({"name": node.name, "line": node.lineno})
        elif isinstance(node, ast.ClassDef):
            classes.append({"name": node.name, "line": node.lineno})
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    return {
        "language": "python",
        "functions": functions,
        "classes": classes,
        "imports": imports,
    }


parse_ast_tool = function_tool(parse_ast)
