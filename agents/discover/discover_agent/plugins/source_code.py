"""SourceCodePlugin — extract endpoints from audited source code.

Wraps the existing source_analyzer.analyze_source() and contributes
discovered routes to the shared SiteMap. Stores extracted routes in
learnings.source_routes for warm start on next session.
"""

import logging

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.source_analyzer import SourceAnalysisResult, analyze_source

logger = logging.getLogger(__name__)


@register_plugin
class SourceCodePlugin(DiscoveryPlugin):
    """Extract API routes from the audited codebase."""

    name = "source_code"
    priority = 20

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        # Run if source analysis was provided or source_routes are available
        return ctx.source_analysis is not None or bool(ctx.source_routes)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()

        # Use pre-computed source analysis if available
        analysis = ctx.source_analysis
        if analysis:
            _extract_from_analysis(analysis, result)

        # Add any directly-provided source routes
        existing = set(result.endpoints)
        for route in ctx.source_routes:
            if route not in existing:
                result.endpoints.append(route)
                existing.add(route)

        # Store in learnings for warm start next session
        if ctx.learnings is not None and result.endpoints:
            new_routes = set(ctx.learnings.source_routes)
            for ep in result.endpoints:
                new_routes.add(ep)
            ctx.learnings.source_routes = sorted(new_routes)

        if result.endpoints:
            logger.info("Source code plugin found %d endpoints", len(result.endpoints))

        return result


def _extract_from_analysis(
    analysis: SourceAnalysisResult, result: DiscoveryResult,
) -> None:
    """Convert SourceAnalysisResult into DiscoveryResult."""
    for route in analysis.routes:
        result.endpoints.append(route.path)
        result.urls.append(route.path)

    # GraphQL endpoints
    if analysis.graphql_queries or analysis.graphql_mutations:
        result.endpoints.append("/graphql")
        result.technologies.append("GraphQL")

    # OpenAPI paths
    for path in analysis.openapi_paths:
        result.endpoints.append(path)
        result.urls.append(path)

    result.technologies.extend(analysis.technologies)
