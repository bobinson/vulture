"""Tests for 8 new framework extractors in source_analyzer.py."""


from discover_agent.source_analyzer import (
    _extract_aspnet_routes,
    _extract_fastapi_routes,
    _extract_laravel_routes,
    _extract_nestjs_routes,
    _extract_phoenix_routes,
    _extract_rails_routes,
    _extract_rust_routes,
    _extract_spring_routes,
    _normalize_route_path,
)


# --- Spring Boot ---


class TestExtractSpringRoutes:
    """Tests for Spring Boot route extraction."""

    def test_get_mapping(self):
        content = '@GetMapping("/api/users")'
        routes = _extract_spring_routes(content, "UserController.java")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "spring"

    def test_post_mapping(self):
        content = '@PostMapping("/api/users")'
        routes = _extract_spring_routes(content, "UserController.java")
        assert routes[0].method == "POST"

    def test_request_mapping_with_value(self):
        content = '@RequestMapping(value="/api/config")'
        routes = _extract_spring_routes(content, "ConfigController.java")
        assert len(routes) == 1
        assert routes[0].path == "/api/config"

    def test_put_delete_patch(self):
        content = """
@PutMapping("/api/users/{id}")
@DeleteMapping("/api/users/{id}")
@PatchMapping("/api/users/{id}")
"""
        routes = _extract_spring_routes(content, "UserController.java")
        assert len(routes) == 3
        methods = {r.method for r in routes}
        assert methods == {"PUT", "DELETE", "PATCH"}

    def test_path_params_already_standard(self):
        content = '@GetMapping("/api/users/{id}/posts")'
        routes = _extract_spring_routes(content, "test.java")
        assert routes[0].path == "/api/users/{id}/posts"


# --- FastAPI ---


class TestExtractFastapiRoutes:
    """Tests for FastAPI route extraction."""

    def test_app_get(self):
        content = '@app.get("/api/users")'
        routes = _extract_fastapi_routes(content, "main.py")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "fastapi"

    def test_router_post(self):
        content = '@router.post("/api/users")'
        routes = _extract_fastapi_routes(content, "routes.py")
        assert routes[0].method == "POST"

    def test_all_methods(self):
        content = """
@app.get("/api/items")
@app.post("/api/items")
@app.put("/api/items/{id}")
@app.delete("/api/items/{id}")
@app.patch("/api/items/{id}")
"""
        routes = _extract_fastapi_routes(content, "main.py")
        assert len(routes) == 5

    def test_path_params(self):
        content = '@app.get("/api/users/{user_id}/items/{item_id}")'
        routes = _extract_fastapi_routes(content, "main.py")
        assert routes[0].path == "/api/users/{user_id}/items/{item_id}"


# --- ASP.NET Core ---


class TestExtractAspnetRoutes:
    """Tests for ASP.NET Core route extraction."""

    def test_http_get_attribute(self):
        content = '[HttpGet("api/users")]'
        routes = _extract_aspnet_routes(content, "UserController.cs")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "aspnet"

    def test_http_post_attribute(self):
        content = '[HttpPost("api/users")]'
        routes = _extract_aspnet_routes(content, "UserController.cs")
        assert routes[0].method == "POST"

    def test_map_get(self):
        content = 'MapGet("/api/health", () => Results.Ok());'
        routes = _extract_aspnet_routes(content, "Program.cs")
        assert len(routes) == 1
        assert routes[0].path == "/api/health"
        assert routes[0].method == "GET"

    def test_map_post(self):
        content = 'MapPost("/api/users", CreateUser);'
        routes = _extract_aspnet_routes(content, "Program.cs")
        assert routes[0].method == "POST"

    def test_combined_attrs_and_maps(self):
        content = """
[HttpGet("api/items")]
[HttpDelete("api/items/{id}")]
MapPut("/api/config", UpdateConfig);
"""
        routes = _extract_aspnet_routes(content, "test.cs")
        assert len(routes) == 3


# --- NestJS ---


class TestExtractNestjsRoutes:
    """Tests for NestJS route extraction."""

    def test_controller_with_get(self):
        content = """
@Controller('users')
@Get('')
"""
        routes = _extract_nestjs_routes(content, "users.controller.ts")
        assert len(routes) == 1
        assert routes[0].path == "/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "nestjs"

    def test_controller_with_sub_path(self):
        content = """
@Controller('api/users')
@Get(':id')
@Post('')
"""
        routes = _extract_nestjs_routes(content, "users.controller.ts")
        assert len(routes) == 2
        paths = {r.path for r in routes}
        assert "/api/users/{id}" in paths
        assert "/api/users" in paths

    def test_param_normalization(self):
        content = """
@Controller('users')
@Get(':userId/posts/:postId')
"""
        routes = _extract_nestjs_routes(content, "test.ts")
        assert routes[0].path == "/users/{userId}/posts/{postId}"

    def test_no_controller(self):
        content = '@Get("/health")'
        routes = _extract_nestjs_routes(content, "health.controller.ts")
        assert len(routes) == 1
        assert routes[0].path == "/health"


# --- Ruby on Rails ---


class TestExtractRailsRoutes:
    """Tests for Ruby on Rails route extraction."""

    def test_get_route(self):
        content = 'get "/api/users", to: "users#index"'
        routes = _extract_rails_routes(content, "routes.rb")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "rails"

    def test_post_route(self):
        content = 'post "/api/users", to: "users#create"'
        routes = _extract_rails_routes(content, "routes.rb")
        assert routes[0].method == "POST"

    def test_resources(self):
        content = "resources :users"
        routes = _extract_rails_routes(content, "routes.rb")
        assert len(routes) == 1
        assert routes[0].path == "/users"
        assert routes[0].method == "ALL"

    def test_param_normalization(self):
        content = 'get "/api/users/:id", to: "users#show"'
        routes = _extract_rails_routes(content, "routes.rb")
        assert routes[0].path == "/api/users/{id}"

    def test_resource_singular(self):
        content = "resource :profile"
        routes = _extract_rails_routes(content, "routes.rb")
        assert len(routes) == 1
        assert routes[0].path == "/profile"


# --- Laravel ---


class TestExtractLaravelRoutes:
    """Tests for Laravel route extraction."""

    def test_route_get(self):
        content = "Route::get('/api/users', [UserController::class, 'index']);"
        routes = _extract_laravel_routes(content, "web.php")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "laravel"

    def test_route_post(self):
        content = "Route::post('/api/users', [UserController::class, 'store']);"
        routes = _extract_laravel_routes(content, "web.php")
        assert routes[0].method == "POST"

    def test_api_resource(self):
        content = "Route::apiResource('/api/items', ItemController::class);"
        routes = _extract_laravel_routes(content, "api.php")
        assert len(routes) == 1
        assert routes[0].path == "/api/items"
        assert routes[0].method == "ALL"

    def test_multiple_routes(self):
        content = """
Route::get('/api/users', 'index');
Route::post('/api/users', 'store');
Route::delete('/api/users/{id}', 'destroy');
"""
        routes = _extract_laravel_routes(content, "api.php")
        assert len(routes) == 3


# --- Rust (Actix/Axum) ---


class TestExtractRustRoutes:
    """Tests for Rust route extraction."""

    def test_route(self):
        content = '.route("/api/users", web::get().to(get_users))'
        routes = _extract_rust_routes(content, "main.rs")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].framework == "rust"

    def test_resource(self):
        content = '.resource("/api/items")'
        routes = _extract_rust_routes(content, "main.rs")
        assert len(routes) == 1
        assert routes[0].path == "/api/items"

    def test_path_params(self):
        content = '.route("/api/users/{id}", web::get().to(get_user))'
        routes = _extract_rust_routes(content, "main.rs")
        assert routes[0].path == "/api/users/{id}"

    def test_multiple_routes(self):
        content = """
.route("/api/health", web::get().to(health))
.route("/api/users", web::get().to(list_users))
.resource("/api/items")
"""
        routes = _extract_rust_routes(content, "main.rs")
        assert len(routes) == 3


# --- Phoenix (Elixir) ---


class TestExtractPhoenixRoutes:
    """Tests for Phoenix/Elixir route extraction."""

    def test_get_route(self):
        content = 'get "/api/users", UserController, :index'
        routes = _extract_phoenix_routes(content, "router.ex")
        assert len(routes) == 1
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[0].framework == "phoenix"

    def test_post_route(self):
        content = 'post "/api/users", UserController, :create'
        routes = _extract_phoenix_routes(content, "router.ex")
        assert routes[0].method == "POST"

    def test_resources(self):
        content = 'resources "/api/items", ItemController'
        routes = _extract_phoenix_routes(content, "router.ex")
        assert len(routes) == 1
        assert routes[0].path == "/api/items"
        assert routes[0].method == "ALL"

    def test_param_normalization(self):
        content = 'get "/api/users/:id", UserController, :show'
        routes = _extract_phoenix_routes(content, "router.ex")
        assert routes[0].path == "/api/users/{id}"


# --- Normalize route path ---


class TestNormalizeRoutePathExtended:
    """Tests for _normalize_route_path with new frameworks."""

    def test_nestjs_colon_params(self):
        assert _normalize_route_path("/users/:id", "nestjs") == "/users/{id}"

    def test_rails_colon_params(self):
        assert _normalize_route_path("/users/:id/posts/:post_id", "rails") == "/users/{id}/posts/{post_id}"

    def test_phoenix_colon_params(self):
        assert _normalize_route_path("/users/:id", "phoenix") == "/users/{id}"

    def test_spring_already_standard(self):
        assert _normalize_route_path("/users/{id}", "spring") == "/users/{id}"

    def test_fastapi_already_standard(self):
        assert _normalize_route_path("/users/{user_id}", "fastapi") == "/users/{user_id}"

    def test_aspnet_already_standard(self):
        assert _normalize_route_path("/users/{id}", "aspnet") == "/users/{id}"

    def test_laravel_already_standard(self):
        assert _normalize_route_path("/users/{id}", "laravel") == "/users/{id}"

    def test_rust_already_standard(self):
        assert _normalize_route_path("/users/{id}", "rust") == "/users/{id}"

    def test_adds_leading_slash(self):
        assert _normalize_route_path("api/users", "spring") == "/api/users"
