---
id: discover/suggest
role: USER
stance: [FORBIDS_PROSE]
declares_fields: [endpoints, reasoning]
exemplars: [endpoints_reasoning_object]
---
You are a web security expert. Given the following discovered information about a web application, suggest additional API endpoints that likely exist but weren't found by automated scanning.

Technologies detected: {technologies}
Known API endpoints: {api_endpoints}
Forms found: {forms}
Response headers: {headers}
Framework signals: {framework_hints}

Based on the technology stack, suggest additional API endpoints that commonly exist. Focus on:
1. REST API CRUD endpoints (GET/POST/PUT/DELETE for known resources)
2. Authentication endpoints (login, register, session, token, refresh, password reset)
3. GraphQL endpoints (common paths, mutations, subscriptions)
4. WebSocket/real-time endpoints
5. Admin/management endpoints
6. File upload/download endpoints
7. Search/filter endpoints
8. Webhook/callback endpoints
9. Health/status/metrics endpoints
10. Configuration/settings endpoints exposed by the framework

Return ONLY a JSON object:
{"endpoints": ["/api/path1", "/api/path2", ...], "reasoning": "brief explanation"}

Rules:
- Only suggest paths starting with /api/, /v1/, /v2/, /graphql, /rest/, /rpc/, /ws/, /auth/
- Do NOT suggest static file paths (.js, .css, images)
- Do NOT suggest HTML page paths (/login, /dashboard, etc.)
- Focus on backend API endpoints that accept/return JSON
- Limit to 20 most likely endpoints