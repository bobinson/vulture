# Discover Agent — Skills

## Overview

The Discover agent maps the attack surface of a target URL using a 25-plugin tiered discovery pipeline, then analyzes the results for security exposures.

## Skills

### endpoint_discovery
Discovers API endpoints, URLs, and forms using a priority-ordered plugin system.

**Plugins (by priority):**

| Pri | Plugin | Discovers |
|-----|--------|-----------|
| 10 | crawl | Homepage, robots.txt, sitemaps, common paths |
| 20 | source_code | Routes from source code analysis |
| 21 | nextjs_config | Rewrites, redirects, security headers |
| 21 | nextjs_app_router | route.ts HTTP method exports |
| 21 | raw_http_handlers | Node/Deno/Bun pathname routing |
| 21 | nextjs_middleware | Matcher, rewrite, redirect targets |
| 22 | infra_config | Docker Compose, K8s, Nginx, Apache configs |
| 23 | mobile_routes | Retrofit, Alamofire, Flutter deep links |
| 24 | nextauth_routes | NextAuth well-known routes |
| 25 | oidc_wellknown | OIDC discovery document endpoints |
| 25 | webhook_receivers | Stripe, GitHub, Slack webhooks |
| 26 | env_service_urls | Env var URL extraction |
| 30 | openapi | OpenAPI/Swagger spec parsing |
| 35 | soap_wsdl | WSDL/SOAP discovery |
| 40 | graphql | Introspection, SDL schemas |
| 50 | websocket | WS, Socket.IO, SignalR |
| 55 | sse | Server-Sent Events paths |
| 60 | rpc | gRPC-Web, JSON-RPC, tRPC |
| 62 | grpc_reflection | gRPC reflection, .proto files |
| 63 | blockchain_rpc | Ethereum, Solana, Bitcoin RPC |
| 65 | mqtt_amqp | MQTT/WS, RabbitMQ, Kafka |
| 70 | js_bundle | API routes from compiled JS |
| 75 | playwright_deep | Headless Chromium deep discovery (XHR/fetch/WS interception) |
| 80 | llm_suggest | LLM-powered hidden endpoint suggestion (requires VULTURE_USE_LLM=true) |
| 90 | endpoint_validation | Parallel HTTP validation of discovered endpoints, 404 removal, method probing |

### security_exposure_analysis
Analyzes the SiteMap for security issues:
- Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)
- Exposed debug/admin endpoints
- GraphQL introspection exposure
- Server version disclosure
- Directory listing risk
- Sensitive file exposure (.env, .git, config files)

### technology_detection
Detects technologies from response headers, HTML content, and JavaScript patterns.

### attack_surface_mapping
Produces a structured SiteMap including:
- API endpoint inventory
- Form action targets with input fields
- Technology fingerprints
- Disallowed paths from robots.txt
- Response header analysis
