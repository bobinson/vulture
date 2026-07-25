"""NextAuthRoutesPlugin — expand NextAuth catch-all into well-known sub-routes.

Detects ``[...nextauth].ts`` catch-all files and expands them into the
8+ well-known NextAuth routes (signin, signout, session, csrf, providers,
error, callback/{provider}).
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import find_files_by_name, has_dependency

logger = logging.getLogger(__name__)

_NEXTAUTH_DEPS = {"next-auth", "@auth/core"}
_NEXTAUTH_FILENAMES = ["[...nextauth].ts", "[...nextauth].js"]

_PROVIDER_ID_RE = re.compile(r"""id:\s*['"]([^'"]+)['"]""")
_BASEPATH_RE = re.compile(r"""basePath:\s*['"]([^'"]+)['"]""")
_PROVIDER_FACTORY_RE = re.compile(
    r"(Google|GitHub|Facebook|Discord|Apple|Slack|Twitter|LinkedIn|Spotify|Auth0)Provider"
)

_DEFAULT_BASE = "/api/auth"
_WELL_KNOWN = ["signin", "signout", "session", "csrf", "providers", "error"]


@register_plugin
class NextAuthRoutesPlugin(DiscoveryPlugin):
    """Expand NextAuth catch-all ``[...nextauth]`` into well-known routes."""

    name = "nextauth_routes"
    priority = 24

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        if not ctx.source_path:
            return False
        root = Path(ctx.source_path)
        if has_dependency(root, _NEXTAUTH_DEPS):
            return True
        return _has_nextauth_file(root)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)

        content = _read_nextauth_file(root)
        base_path = _detect_base_path(content) if content else _DEFAULT_BASE
        providers = _extract_providers(content) if content else []
        version = _detect_version(root)

        _emit_well_known(result, base_path)
        _emit_callback_routes(result, base_path, providers)

        result.technologies.append("NextAuth")
        result.metadata["nextauth_base"] = base_path
        result.metadata["nextauth_version"] = version
        if providers:
            result.metadata["nextauth_providers"] = providers

        logger.info("NextAuthRoutes: found %d endpoints", len(result.endpoints))
        return result


def _has_nextauth_file(root: Path) -> bool:
    """Check if any [...nextauth] file exists."""
    for name in _NEXTAUTH_FILENAMES:
        if find_files_by_name(root, name, max_results=1):
            return True
    return False


def _read_nextauth_file(root: Path) -> str | None:
    """Read the first [...nextauth] file found."""
    for name in _NEXTAUTH_FILENAMES:
        files = find_files_by_name(root, name, max_results=1)
        if files:
            try:
                return files[0].read_text(errors="replace")
            except Exception:
                continue
    return None


def _detect_base_path(content: str) -> str:
    """Extract custom basePath or return default."""
    m = _BASEPATH_RE.search(content)
    return m.group(1) if m else _DEFAULT_BASE


def _extract_providers(content: str) -> list[str]:
    """Extract provider IDs from NextAuth config."""
    providers: set[str] = set()
    for m in _PROVIDER_ID_RE.finditer(content):
        providers.add(m.group(1))
    for m in _PROVIDER_FACTORY_RE.finditer(content):
        providers.add(m.group(1).lower())
    return sorted(providers)


def _detect_version(root: Path) -> str:
    """Detect NextAuth version from package.json."""
    pkg_path = root / "package.json"
    if not pkg_path.is_file():
        return "unknown"
    try:
        import json
        data = json.loads(pkg_path.read_text(errors="replace"))
    except Exception:
        return "unknown"
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    if "@auth/core" in deps:
        return "v5"
    if "next-auth" in deps:
        ver = deps["next-auth"]
        return "v5" if ver.startswith("5") or ver.startswith("^5") else "v4"
    return "unknown"


def _emit_well_known(result: DiscoveryResult, base: str) -> None:
    """Add the standard NextAuth well-known routes."""
    for name in _WELL_KNOWN:
        result.endpoints.append(f"{base}/{name}")


def _emit_callback_routes(
    result: DiscoveryResult, base: str, providers: list[str],
) -> None:
    """Add callback routes for each detected provider."""
    for provider in providers:
        result.endpoints.append(f"{base}/callback/{provider}")
