"""Dependency checker tool for agents."""

import json
import re
from pathlib import Path

from agents import function_tool


def check_dependencies(path: str) -> dict:
    """Check project dependencies from manifest files.

    Scans for requirements.txt, package.json, and go.mod.

    Args:
        path: Root directory of the project.

    Returns:
        Dict with 'dependencies' list of {name, version, source} dicts.
    """
    root = Path(path)
    deps: list[dict] = []

    _parse_requirements_txt(root, deps)
    _parse_package_json(root, deps)
    _parse_go_mod(root, deps)

    return {"dependencies": deps}


def _parse_requirements_txt(root: Path, deps: list[dict]) -> None:
    """Parse requirements.txt."""
    req_file = root / "requirements.txt"
    if not req_file.is_file():
        return
    for line in req_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"([a-zA-Z0-9_-]+)(.*)", line)
        if match:
            deps.append({
                "name": match.group(1),
                "version": match.group(2).strip(),
                "source": "requirements.txt",
            })


def _parse_package_json(root: Path, deps: list[dict]) -> None:
    """Parse package.json."""
    pkg_file = root / "package.json"
    if not pkg_file.is_file():
        return
    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append({"name": name, "version": version, "source": "package.json"})


def _parse_go_mod(root: Path, deps: list[dict]) -> None:
    """Parse go.mod."""
    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return
    in_require = False
    for line in go_mod.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("require"):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require and stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append({
                    "name": parts[0],
                    "version": parts[1],
                    "source": "go.mod",
                })


check_dependencies_tool = function_tool(check_dependencies)
