"""NextJSAppRouterPlugin — discover endpoints from Next.js App Router route.ts files.

Finds ``app/**/route.ts`` files, converts directory paths to URL routes,
and extracts exported HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.).
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import find_files_by_name

logger = logging.getLogger(__name__)

_HTTP_EXPORT_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
)
_HTTP_CONST_RE = re.compile(
    r"export\s+const\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*="
)
_ROUTE_GROUP_RE = re.compile(r"\([^)]+\)")  # (auth) → stripped
_DYNAMIC_SEGMENT_RE = re.compile(r"\[([^\]]+)\]")  # [id] → {id}
_SLOT_PREFIX = "@"


@register_plugin
class NextJSAppRouterPlugin(DiscoveryPlugin):
    """Discover API routes from Next.js App Router ``route.ts`` files."""

    name = "nextjs_app_router"
    priority = 21

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        if not ctx.source_path:
            return False
        root = Path(ctx.source_path)
        return (root / "app").is_dir() or (root / "src" / "app").is_dir()

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        app_dir = _find_app_dir(root)
        if not app_dir:
            return result

        route_files = _find_route_files(root)
        routes: list[dict] = []

        for fpath in route_files:
            route_path = _dir_to_route(fpath, app_dir)
            if not route_path:
                continue
            methods = _extract_methods(fpath)
            routes.append({"path": route_path, "methods": methods})
            result.endpoints.append(route_path)

        result.technologies.append("Next.js App Router")
        if routes:
            result.metadata["app_router_routes"] = routes

        if result.endpoints:
            logger.info("NextJSAppRouter: found %d routes", len(result.endpoints))
        return result


def _find_app_dir(root: Path) -> Path | None:
    """Locate the app directory at root/ or root/src/."""
    for candidate in [root / "app", root / "src" / "app"]:
        if candidate.is_dir():
            return candidate
    return None


def _find_route_files(root: Path) -> list[Path]:
    """Find all route.ts and route.js files."""
    results: list[Path] = []
    results.extend(find_files_by_name(root, "route.ts"))
    results.extend(find_files_by_name(root, "route.js"))
    return results


def _dir_to_route(fpath: Path, app_dir: Path) -> str:
    """Convert a route file's directory path to a URL route.

    ``app/(auth)/api/users/[id]/route.ts`` → ``/api/users/{id}``
    """
    try:
        rel = fpath.parent.relative_to(app_dir)
    except ValueError:
        return ""

    parts: list[str] = []
    for segment in rel.parts:
        if segment.startswith(_SLOT_PREFIX):
            continue
        cleaned = _ROUTE_GROUP_RE.sub("", segment)
        if not cleaned:
            continue
        cleaned = _DYNAMIC_SEGMENT_RE.sub(r"{\1}", cleaned)
        parts.append(cleaned)

    return "/" + "/".join(parts) if parts else "/"


def _extract_methods(fpath: Path) -> list[str]:
    """Extract exported HTTP method names from a route file."""
    try:
        content = fpath.read_text(errors="replace")
    except Exception:
        return []

    methods: set[str] = set()
    for m in _HTTP_EXPORT_RE.finditer(content):
        methods.add(m.group(1))
    for m in _HTTP_CONST_RE.finditer(content):
        methods.add(m.group(1))
    return sorted(methods)
