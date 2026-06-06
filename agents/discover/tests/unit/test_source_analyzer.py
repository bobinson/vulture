"""Tests for source code endpoint extraction."""

import tempfile
from pathlib import Path


from discover_agent.source_analyzer import (
    SourceAnalysisResult,
    SourceRoute,
    _extract_django_routes,
    _extract_express_routes,
    _extract_flask_routes,
    _extract_go_routes,
    _extract_graphql_schema,
    _extract_nextjs_routes,
    _extract_openapi_spec,
    _normalize_route_path,
    analyze_source,
    format_source_analysis,
)


# --- Express ---

class TestExtractExpressRoutes:
    def test_app_get_pattern(self):
        content = "app.get('/api/users', handler)"
        routes = _extract_express_routes(content, "server.js")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"

    def test_router_post_pattern(self):
        content = "router.post('/api/items', create)"
        routes = _extract_express_routes(content, "routes.js")
        assert len(routes) == 1
        assert routes[0].path == "/api/items"
        assert routes[0].method == "POST"

    def test_multiple_routes_in_file(self):
        content = """
app.get('/api/users', listUsers)
app.post('/api/users', createUser)
app.delete('/api/users/:id', deleteUser)
"""
        routes = _extract_express_routes(content, "app.js")
        assert len(routes) == 3
        assert routes[2].path == "/api/users/{id}"
        assert routes[2].method == "DELETE"

    def test_use_becomes_all(self):
        content = "app.use('/api/middleware', mw)"
        routes = _extract_express_routes(content, "app.js")
        assert len(routes) == 1
        assert routes[0].method == "ALL"

    def test_param_normalization(self):
        content = "app.get('/api/users/:userId/posts/:postId', handler)"
        routes = _extract_express_routes(content, "app.js")
        assert routes[0].path == "/api/users/{userId}/posts/{postId}"


# --- Next.js ---

class TestExtractNextjsRoutes:
    def test_pages_api_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            api_dir = root / "pages" / "api" / "users"
            api_dir.mkdir(parents=True)
            (api_dir / "index.ts").write_text("export default handler")
            (api_dir / "[id].ts").write_text("export default handler")
            files = list(root.rglob("*.ts"))
            routes = _extract_nextjs_routes(files, root)
            paths = {r.path for r in routes}
            assert "/api/users" in paths
            assert "/api/users/{id}" in paths

    def test_catch_all_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            api_dir = root / "pages" / "api" / "auth"
            api_dir.mkdir(parents=True)
            (api_dir / "[...nextauth].ts").write_text("export default handler")
            files = list(root.rglob("*.ts"))
            routes = _extract_nextjs_routes(files, root)
            assert len(routes) == 1
            assert routes[0].path == "/api/auth/{nextauth}"

    def test_app_api_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            api_dir = root / "src" / "app" / "api" / "health"
            api_dir.mkdir(parents=True)
            (api_dir / "route.ts").write_text("export async function GET() {}")
            files = list(root.rglob("*.ts"))
            routes = _extract_nextjs_routes(files, root)
            assert len(routes) == 1
            assert routes[0].path == "/api/health/route"


# --- Django ---

class TestExtractDjangoRoutes:
    def test_urlpatterns_path(self):
        content = """
urlpatterns = [
    path('api/users/', views.user_list),
    path('api/users/<int:pk>/', views.user_detail),
]
"""
        routes = _extract_django_routes(content, "urls.py")
        assert len(routes) == 2
        assert routes[0].path == "/api/users"
        assert routes[1].path == "/api/users/{pk}"

    def test_str_param(self):
        content = "path('api/posts/<str:slug>/', views.post)"
        routes = _extract_django_routes(content, "urls.py")
        assert routes[0].path == "/api/posts/{slug}"


# --- Flask ---

class TestExtractFlaskRoutes:
    def test_app_route_decorator(self):
        content = "@app.route('/api/items')"
        routes = _extract_flask_routes(content, "app.py")
        assert len(routes) == 1
        assert routes[0].method == "ALL"

    def test_blueprint_get(self):
        content = "@bp.get('/api/items/<int:id>')"
        routes = _extract_flask_routes(content, "views.py")
        assert len(routes) == 1
        assert routes[0].method == "GET"
        assert routes[0].path == "/api/items/{id}"


# --- Go ---

class TestExtractGoRoutes:
    def test_handlefunc(self):
        content = 'mux.HandleFunc("/api/users", handler)'
        routes = _extract_go_routes(content, "main.go")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"

    def test_chi_get(self):
        content = 'r.Get("/api/health", healthCheck)'
        routes = _extract_go_routes(content, "routes.go")
        assert len(routes) == 1
        assert routes[0].path == "/api/health"

    def test_gin_post(self):
        content = 'r.POST("/api/login", loginHandler)'
        routes = _extract_go_routes(content, "main.go")
        assert len(routes) == 1


# --- GraphQL ---

class TestExtractGraphqlSchema:
    def test_query_type(self):
        content = """
type Query {
    users: [User]
    user(id: ID!): User
    me: User
}
"""
        types, queries, mutations = _extract_graphql_schema(content, "schema.graphql")
        assert "Query" in types
        assert "users" in queries
        assert "user" in queries
        assert "me" in queries

    def test_mutation_type(self):
        content = """
type Mutation {
    createUser(input: CreateUserInput!): User
    deleteUser(id: ID!): Boolean
}
"""
        types, queries, mutations = _extract_graphql_schema(content, "schema.graphql")
        assert "Mutation" in types
        assert "createUser" in mutations
        assert "deleteUser" in mutations

    def test_both_query_and_mutation(self):
        content = """
type Query {
    posts: [Post]
}
type Mutation {
    createPost(title: String!): Post
}
"""
        types, queries, mutations = _extract_graphql_schema(content, "schema.gql")
        assert len(queries) == 1
        assert len(mutations) == 1


# --- OpenAPI ---

class TestExtractOpenapiSpec:
    def test_openapi_json_paths(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {"get": {}, "post": {}},
                "/api/users/{id}": {"get": {}, "delete": {}},
            },
        }
        import json
        paths = _extract_openapi_spec(json.dumps(spec))
        assert "/api/users" in paths
        assert "/api/users/{id}" in paths

    def test_swagger_with_basepath(self):
        spec = {
            "swagger": "2.0",
            "basePath": "/v1",
            "paths": {"/users": {}, "/items": {}},
        }
        import json
        paths = _extract_openapi_spec(json.dumps(spec))
        assert "/v1/users" in paths
        assert "/v1/items" in paths

    def test_invalid_json(self):
        assert _extract_openapi_spec("not json") == []


# --- Normalize ---

class TestNormalizeRoutePath:
    def test_express_params(self):
        assert _normalize_route_path("/users/:id", "express") == "/users/{id}"

    def test_django_params(self):
        assert _normalize_route_path("/users/<int:pk>", "django") == "/users/{pk}"

    def test_flask_params(self):
        assert _normalize_route_path("/items/<name>", "flask") == "/items/{name}"

    def test_adds_leading_slash(self):
        assert _normalize_route_path("api/users", "express") == "/api/users"


# --- Full pipeline ---

class TestAnalyzeSource:
    def test_express_app(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text('{"dependencies": {"express": "^4.0"}}')
            (root / "server.js").write_text("""
const app = require('express')();
app.get('/api/users', handler);
app.post('/api/users', handler);
""")
            result = analyze_source(tmpdir)
            assert result.framework == "express"
            assert len(result.routes) == 2

    def test_graphql_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text("{}")
            schema = root / "schema.graphql"
            schema.write_text("""
type Query {
    users: [User]
    me: User
}
type Mutation {
    login(email: String!, password: String!): AuthPayload
}
""")
            result = analyze_source(tmpdir)
            assert "users" in result.graphql_queries
            assert "me" in result.graphql_queries
            assert "login" in result.graphql_mutations

    def test_nonexistent_path(self):
        result = analyze_source("/nonexistent/path/xyz")
        assert result.routes == []
        assert result.framework == ""


# --- Format ---

class TestFormatSourceAnalysis:
    def test_with_routes(self):
        result = SourceAnalysisResult(
            framework="express",
            routes=[SourceRoute(path="/api/users", method="GET", framework="express")],
            graphql_queries=["me", "users"],
        )
        text = format_source_analysis(result)
        assert "express" in text
        assert "/api/users" in text
        assert "me" in text

    def test_empty_result(self):
        assert format_source_analysis(SourceAnalysisResult()) == ""
