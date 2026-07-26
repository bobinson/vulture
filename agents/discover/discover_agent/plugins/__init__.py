"""Plugin-based discovery system for extensible endpoint detection.

Each discovery method (crawl, OpenAPI, GraphQL, WebSocket, RPC, etc.)
is a separate plugin that can be independently developed and tested.
Plugins run in priority order, each contributing to a shared SiteMap.

Usage:
    from discover_agent.plugins import run_discovery, DiscoveryContext
    ctx = DiscoveryContext(staging_url=url, http_client=client, site=SiteMap())
    site, failed = await run_discovery(ctx)
"""

import logging

from shared.discovery.plugin_base import (  # noqa: F401
    DISCOVERY_PLUGINS,
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)
from shared.discovery.plugin_base import (
    merge_result as _merge_result,  # noqa: F401
)
from shared.discovery.runner import run_discovery  # noqa: F401
from shared.discovery.sitemap import SiteMap  # noqa: F401

logger = logging.getLogger(__name__)


# Import plugins to trigger registration via @register_plugin decorator.
# Each module's @register_plugin call adds the plugin to DISCOVERY_PLUGINS.
# Ordered by priority for readability.
from discover_agent.plugins.blockchain_rpc import (  # noqa: E402
    BlockchainRPCPlugin as _BlockchainRPCPlugin,  # noqa: F401
)
from discover_agent.plugins.crawl import CrawlPlugin as _CrawlPlugin  # noqa: E402, F401
from discover_agent.plugins.endpoint_validation import (  # noqa: E402
    EndpointValidationPlugin as _EndpointValidationPlugin,  # noqa: F401
)
from discover_agent.plugins.env_service_urls import (  # noqa: E402
    EnvServiceURLsPlugin as _EnvServiceURLsPlugin,  # noqa: F401
)
from discover_agent.plugins.graphql import GraphQLPlugin as _GraphQLPlugin  # noqa: E402, F401
from discover_agent.plugins.grpc_reflection import (  # noqa: E402
    GRPCReflectionPlugin as _GRPCReflectionPlugin,  # noqa: F401
)
from discover_agent.plugins.infra_config import (  # noqa: E402
    InfraConfigPlugin as _InfraConfigPlugin,  # noqa: F401
)
from discover_agent.plugins.js_bundle import JSBundlePlugin as _JSBundlePlugin  # noqa: E402, F401
from discover_agent.plugins.llm_suggest import (  # noqa: E402
    LLMEndpointPlugin as _LLMEndpointPlugin,  # noqa: F401
)
from discover_agent.plugins.mobile_routes import (  # noqa: E402
    MobileRoutesPlugin as _MobileRoutesPlugin,  # noqa: F401
)
from discover_agent.plugins.mqtt_amqp import MQTTAMQPPlugin as _MQTTAMQPPlugin  # noqa: E402, F401
from discover_agent.plugins.nextauth_routes import (  # noqa: E402
    NextAuthRoutesPlugin as _NextAuthRoutesPlugin,  # noqa: F401
)
from discover_agent.plugins.nextjs_app_router import (  # noqa: E402
    NextJSAppRouterPlugin as _NextJSAppRouterPlugin,  # noqa: F401
)
from discover_agent.plugins.nextjs_config import (  # noqa: E402
    NextJSConfigPlugin as _NextJSConfigPlugin,  # noqa: F401
)
from discover_agent.plugins.nextjs_middleware import (  # noqa: E402
    NextJSMiddlewarePlugin as _NextJSMiddlewarePlugin,  # noqa: F401
)
from discover_agent.plugins.oidc_wellknown import (  # noqa: E402
    OIDCWellKnownPlugin as _OIDCWellKnownPlugin,  # noqa: F401
)
from discover_agent.plugins.openapi import OpenAPIPlugin as _OpenAPIPlugin  # noqa: E402, F401
from discover_agent.plugins.playwright_deep import (  # noqa: E402
    PlaywrightDeepPlugin as _PlaywrightDeepPlugin,  # noqa: F401
)
from discover_agent.plugins.raw_http_handlers import (  # noqa: E402
    RawHTTPHandlersPlugin as _RawHTTPHandlersPlugin,  # noqa: F401
)
from discover_agent.plugins.rpc import RPCPlugin as _RPCPlugin  # noqa: E402, F401
from discover_agent.plugins.soap_wsdl import SOAPWSDLPlugin as _SOAPWSDLPlugin  # noqa: E402, F401
from discover_agent.plugins.source_code import (  # noqa: E402
    SourceCodePlugin as _SourceCodePlugin,  # noqa: F401
)
from discover_agent.plugins.sse import SSEPlugin as _SSEPlugin  # noqa: E402, F401
from discover_agent.plugins.webhook_receivers import (  # noqa: E402
    WebhookReceiversPlugin as _WebhookReceiversPlugin,  # noqa: F401
)
from discover_agent.plugins.websocket import WebSocketPlugin as _WebSocketPlugin  # noqa: E402, F401
