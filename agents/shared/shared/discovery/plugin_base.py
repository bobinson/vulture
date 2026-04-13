"""Discovery plugin base classes and registry."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from shared.discovery.sitemap import SiteMap

if TYPE_CHECKING:
    pass


@dataclass
class DiscoveryContext:
    """Shared context passed to all discovery plugins."""

    staging_url: str
    http_client: httpx.AsyncClient
    site: SiteMap
    learnings: object | None = None  # SessionLearnings from prove_agent
    source_routes: list[str] = field(default_factory=list)
    schemas: dict[str, str] = field(default_factory=dict)
    source_analysis: object | None = None  # SourceAnalysisResult from prove_agent
    source_path: str = ""
    rate_limit: float = 0.0  # Delay in seconds between HTTP requests (0 = no limit)


@dataclass
class DiscoveryResult:
    """Output from a single plugin's discovery pass."""

    endpoints: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class DiscoveryPlugin(ABC):
    """Base class for all discovery plugins."""

    name: str = ""
    priority: int = 100

    @abstractmethod
    async def accepts(self, ctx: DiscoveryContext) -> bool:
        """Return True if this plugin should run given current context."""

    @abstractmethod
    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        """Run discovery and return found endpoints."""


# --- Plugin registry ---

DISCOVERY_PLUGINS: list[type[DiscoveryPlugin]] = []
_registry_lock = threading.Lock()


def register_plugin(cls: type[DiscoveryPlugin]) -> type[DiscoveryPlugin]:
    """Decorator to register a discovery plugin (thread-safe)."""
    with _registry_lock:
        DISCOVERY_PLUGINS.append(cls)
        DISCOVERY_PLUGINS.sort(key=lambda p: p.priority)
    return cls


def merge_result(site: SiteMap, result: DiscoveryResult) -> None:
    """Merge a plugin's DiscoveryResult into the shared SiteMap."""
    existing_urls = set(site.urls)
    for u in result.urls:
        if u not in existing_urls:
            site.urls.append(u)

    existing_api = set(site.api_endpoints)
    for ep in result.endpoints:
        if ep not in existing_api:
            site.api_endpoints.append(ep)

    existing_forms = {f.get("action", "") + "|" + f.get("method", "") for f in site.forms}
    for f in result.forms:
        key = f.get("action", "") + "|" + f.get("method", "")
        if key not in existing_forms:
            site.forms.append(f)

    existing_tech = set(site.technologies)
    for t in result.technologies:
        if t not in existing_tech:
            site.technologies.append(t)
