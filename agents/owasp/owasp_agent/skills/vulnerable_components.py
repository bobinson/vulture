"""Vulnerable components detection skill (A06)."""

import re

from agents import function_tool

from shared.tools.dependency_checker import check_dependencies

KNOWN_VULNERABLE: dict[str, tuple[int, ...]] = {
    "pyyaml": (6, 0),
    "requests": (2, 31, 0),
    "django": (4, 2),
    "flask": (2, 3),
    "lodash": (4, 17, 21),
    "express": (4, 18),
}

_VERSION_STRIP = re.compile(r"^[^0-9]*")


def check_vulnerable_components(source_path: str) -> dict:
    """Check for known-vulnerable dependency versions.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of vulnerable component issues.
    """
    result = check_dependencies(source_path)
    findings: list[dict] = []

    for dep in result.get("dependencies", []):
        _check_dep(dep, findings)

    return {"findings": findings}


def _check_dep(dep: dict, findings: list[dict]) -> None:
    """Check a single dependency against known-vulnerable versions."""
    name = dep["name"].lower()
    threshold = KNOWN_VULNERABLE.get(name)
    if threshold is None:
        return

    version_tuple = _parse_version(dep.get("version", ""))
    if not version_tuple:
        return

    if version_tuple < threshold:
        findings.append({
            "severity": "high",
            "category": "A06-vulnerable-components",
            "title": f"Vulnerable dependency: {dep['name']}",
            "description": f"{dep['name']} {dep['version']} is below safe version {'.'.join(str(v) for v in threshold)}",
            "file_path": dep.get("source", ""),
            "line_start": 1,
            "line_end": 1,
            "recommendation": f"Upgrade {dep['name']} to at least {'.'.join(str(v) for v in threshold)}",
        })


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple of ints."""
    cleaned = _VERSION_STRIP.sub("", version_str.strip())
    if not cleaned:
        return None
    parts = []
    for part in cleaned.split("."):
        digits = re.match(r"(\d+)", part)
        if digits:
            parts.append(int(digits.group(1)))
    return tuple(parts) if parts else None


check_vulnerable_components_tool = function_tool(check_vulnerable_components)
