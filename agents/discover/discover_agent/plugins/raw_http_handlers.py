"""RawHTTPHandlersPlugin — discover endpoints from raw Node/Deno/Bun pathname routing.

Scans JavaScript/TypeScript files for ``pathname === "/path"`` and similar
patterns used in raw ``http.createServer``, ``Deno.serve``, and ``Bun.serve``
handlers that are invisible to framework-aware extractors.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_MAX_FILES = 200
_JS_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs"}
_CONTEXT_LINES = 5

_PATHNAME_PATTERNS = [
    re.compile(r"""pathname\s*===?\s*['"]([^'"]+)['"]"""),
    re.compile(r"""pathname\.startsWith\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""req\.url\s*===?\s*['"]([^'"]+)['"]"""),
    re.compile(r"""url\.pathname\s*===?\s*['"]([^'"]+)['"]"""),
    re.compile(r"""url\.pathname\.startsWith\s*\(\s*['"]([^'"]+)['"]"""),
]
_METHOD_RE = re.compile(r"""req\.method\s*===?\s*['"](\w+)['"]""")
_SERVER_CREATE_RE = re.compile(r"(?:http\.createServer|createServer|Deno\.serve|Bun\.serve)")


@register_plugin
class RawHTTPHandlersPlugin(DiscoveryPlugin):
    """Discover routes from raw Node.js/Deno/Bun pathname routing."""

    name = "raw_http_handlers"
    priority = 21

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return bool(ctx.source_path)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        if not root.is_dir():
            return result

        routes: list[dict] = []
        techs: set[str] = set()
        _scan_all_files(root, routes, techs)

        seen: set[str] = set()
        for route in routes:
            path = route["path"]
            if path not in seen:
                result.endpoints.append(path)
                seen.add(path)
        result.technologies = sorted(techs)
        if routes:
            result.metadata["raw_http_routes"] = routes

        if result.endpoints:
            logger.info("RawHTTPHandlers: found %d endpoints", len(result.endpoints))
        return result


def _scan_all_files(
    root: Path, routes: list[dict], techs: set[str],
) -> None:
    """Walk JS/TS files looking for pathname routing patterns."""
    scanned = 0
    for fpath in root.rglob("*"):
        if scanned >= _MAX_FILES:
            break
        if not _is_scannable(fpath):
            continue
        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            continue
        scanned += 1
        _scan_file(content, fpath, root, routes, techs)


def _is_scannable(fpath: Path) -> bool:
    """Check if a file should be scanned."""
    if not fpath.is_file() or fpath.suffix not in _JS_EXTENSIONS:
        return False
    return not _is_excluded(fpath)


def _is_excluded(fpath: Path) -> bool:
    """Skip node_modules, dist, build, .next directories."""
    parts = fpath.parts
    return any(p in ("node_modules", "dist", "build", ".next") for p in parts)


def _scan_file(
    content: str, fpath: Path, root: Path,
    routes: list[dict], techs: set[str],
) -> None:
    """Scan a single file for pathname patterns and server creation."""
    lines = content.splitlines()
    for i, line in enumerate(lines):
        for pattern in _PATHNAME_PATTERNS:
            for m in pattern.finditer(line):
                path = m.group(1)
                if not path.startswith("/"):
                    continue
                method = _detect_method(lines, i)
                rel = str(fpath.relative_to(root))
                routes.append({"path": path, "method": method, "file": rel})

    _detect_server_tech(content, techs)


def _detect_method(lines: list[str], idx: int) -> str:
    """Scan nearby lines for req.method checks."""
    start = max(0, idx - _CONTEXT_LINES)
    end = min(len(lines), idx + _CONTEXT_LINES + 1)
    for line in lines[start:end]:
        m = _METHOD_RE.search(line)
        if m:
            return m.group(1)
    return "GET"


def _detect_server_tech(content: str, techs: set[str]) -> None:
    """Detect server creation pattern for technology tagging."""
    if not _SERVER_CREATE_RE.search(content):
        return
    if "Deno.serve" in content:
        techs.add("Deno")
    elif "Bun.serve" in content:
        techs.add("Bun")
    else:
        techs.add("Node.js HTTP")
