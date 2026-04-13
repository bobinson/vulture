"""Source code endpoint extraction — deterministic, no LLM needed.

Parses the audited codebase to find route definitions, GraphQL schemas,
and API endpoint declarations. Runs BEFORE HTTP discovery to produce
"expected endpoints" that discovery then validates.

Supported frameworks: Express, Next.js, Django, Flask, Go (chi/gin/echo/mux),
Spring Boot, FastAPI, ASP.NET Core, NestJS, Ruby on Rails, Laravel,
Rust (Actix/Axum), Phoenix (Elixir), GraphQL SDL, OpenAPI/Swagger specs.
"""

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from shared.tools.file_scanner import CODE_EXTENSIONS, read_file_safe, scan_code_files

logger = logging.getLogger(__name__)

_MAX_SCAN_FILES = 500

# Extend default code extensions to include GraphQL, proto, WSDL, mobile
_SOURCE_EXTENSIONS = CODE_EXTENSIONS | frozenset({
    ".graphql", ".gql",
    ".kt", ".kts",       # Kotlin (Spring Boot, Android)
    ".ex", ".exs",        # Elixir (Phoenix)
    ".dart",              # Dart (Flutter)
    ".swift",             # Swift (iOS)
    ".proto",             # Protocol Buffers (gRPC)
    ".wsdl",              # SOAP/WSDL
})


@dataclass
class SourceRoute:
    """An endpoint discovered from source code analysis."""

    path: str
    method: str = "GET"
    framework: str = ""
    file_path: str = ""
    line_number: int = 0
    route_type: str = "rest"  # rest, graphql, websocket, rpc


@dataclass
class SourceAnalysisResult:
    """Complete results of source code endpoint extraction."""

    routes: list[SourceRoute] = field(default_factory=list)
    graphql_types: list[str] = field(default_factory=list)
    graphql_queries: list[str] = field(default_factory=list)
    graphql_mutations: list[str] = field(default_factory=list)
    openapi_paths: list[str] = field(default_factory=list)
    framework: str = ""
    technologies: list[str] = field(default_factory=list)


def analyze_source(source_path: str) -> SourceAnalysisResult:
    """Scan source code and extract all endpoint definitions."""
    root = Path(source_path)
    if not root.is_dir():
        return SourceAnalysisResult()

    files = scan_code_files(source_path, extensions=_SOURCE_EXTENSIONS, max_files=_MAX_SCAN_FILES)
    result = SourceAnalysisResult()
    result.framework = _detect_framework(files, root)

    _extract_all_routes(files, root, result)
    _build_technologies(result)
    result.routes = _deduplicate_routes(result.routes)

    logger.info(
        "Source analysis: %d routes, %d GQL queries, %d GQL mutations, framework=%s",
        len(result.routes), len(result.graphql_queries),
        len(result.graphql_mutations), result.framework,
    )
    return result


def _extract_all_routes(files: list[Path], root: Path, result: SourceAnalysisResult) -> None:
    """Extract routes from all source files using framework-specific + universal extractors."""
    extractor = _EXTRACTORS.get(result.framework)

    def _read_and_extract(f: Path) -> None:
        content = read_file_safe(f)
        if not content:
            return
        _extract_file_routes(f, content, extractor, result)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_read_and_extract, files))

    if result.framework == "nextjs":
        result.routes.extend(_extract_nextjs_routes(files, root))


_OPENAPI_NAMES = frozenset({"openapi.json", "swagger.json", "openapi.yaml", "swagger.yaml"})


def _extract_file_routes(
    f: Path, content: str, extractor: object | None, result: SourceAnalysisResult,
) -> None:
    """Extract routes from a single file."""
    fp = str(f)
    if extractor and result.framework != "nextjs":
        result.routes.extend(extractor(content, fp))
    if _is_graphql_file(f, content):
        types, queries, mutations = _extract_graphql_schema(content, fp)
        result.graphql_types.extend(types)
        result.graphql_queries.extend(queries)
        result.graphql_mutations.extend(mutations)
    if f.name in _OPENAPI_NAMES:
        result.openapi_paths.extend(_extract_openapi_spec(content))


def _build_technologies(result: SourceAnalysisResult) -> None:
    """Populate technologies list from analysis result."""
    if result.framework:
        result.technologies.append(result.framework)
    if result.graphql_queries or result.graphql_mutations:
        result.technologies.append("GraphQL")


def _deduplicate_routes(routes: list[SourceRoute]) -> list[SourceRoute]:
    """Deduplicate routes by (path, method) pair."""
    seen: set[tuple[str, str]] = set()
    unique: list[SourceRoute] = []
    for r in routes:
        key = (r.path, r.method)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def _detect_framework(files: list[Path], root: Path) -> str:
    """Detect the primary framework from file patterns.

    Uses a two-pass approach:
      1. Fast checks from filenames and directory structure
      2. Content-based checks on specific files
    """
    names = {f.name for f in files}
    ctx = _DetectionContext(files, names, root)

    # Pass 1: Filename/structure-based (no I/O)
    result = _detect_from_structure(ctx)
    if result:
        return result

    # Pass 2: Content-based (reads files)
    return _detect_from_content(ctx)


@dataclass
class _DetectionContext:
    """Context for framework detection."""
    files: list[Path]
    names: set[str]
    root: Path


def _detect_from_structure(ctx: _DetectionContext) -> str:
    """Fast detection from filenames and directory structure."""
    rel_dirs = _collect_rel_dirs(ctx.files, ctx.root)
    for check_fn in _STRUCTURE_CHECKS:
        result = check_fn(ctx, rel_dirs)
        if result:
            return result
    return ""


def _collect_rel_dirs(files: list[Path], root: Path) -> set[str]:
    """Build the set of relative directory paths."""
    rel_dirs: set[str] = set()
    for f in files:
        try:
            rel = f.relative_to(root)
            rel_dirs.update(str(p) for p in rel.parents)
        except ValueError:
            pass
    return rel_dirs


def _check_nextjs(ctx: _DetectionContext, rel_dirs: set[str]) -> str:
    if ctx.names & {"next.config.js", "next.config.ts", "next.config.mjs"}:
        return "nextjs"
    if any("pages/api" in d or "app/api" in d for d in rel_dirs):
        return "nextjs"
    return ""


def _check_django(ctx: _DetectionContext, _rel_dirs: set[str]) -> str:
    if "manage.py" in ctx.names and any(f.name == "urls.py" for f in ctx.files):
        return "django"
    return ""


def _check_go(ctx: _DetectionContext, _rel_dirs: set[str]) -> str:
    return "go" if "go.mod" in ctx.names else ""


def _check_rails(ctx: _DetectionContext, _rel_dirs: set[str]) -> str:
    if any("config/routes.rb" in str(f) for f in ctx.files):
        return "rails"
    return ""


def _check_laravel(ctx: _DetectionContext, _rel_dirs: set[str]) -> str:
    if "artisan" in ctx.names and any("routes" in str(f.parent.name) for f in ctx.files):
        return "laravel"
    return ""


_STRUCTURE_CHECKS = [_check_nextjs, _check_django, _check_go, _check_rails, _check_laravel]


# File-content detectors: (filename_set, content_marker, framework_name)
_FILE_CONTENT_DETECTORS: list[tuple[set[str], str, str]] = [
    ({"app.py", "__init__.py"}, "from flask", "flask"),
    ({"app.py", "__init__.py", "main.py"}, "from fastapi", "fastapi"),
    ({"app.py", "__init__.py", "main.py"}, "import fastapi", "fastapi"),
    ({"pom.xml", "build.gradle", "build.gradle.kts"}, "spring-boot", "spring"),
]

# Root-file detectors: (filename, content_marker, framework_name)
_ROOT_FILE_DETECTORS: list[tuple[str, str, str]] = [
    ("Cargo.toml", "actix-web", "rust"),
    ("Cargo.toml", "axum", "rust"),
    ("mix.exs", "phoenix", "phoenix"),
]


def _detect_from_content(ctx: _DetectionContext) -> str:
    """Content-based detection reading specific files."""
    result = _detect_node_framework(ctx.root)
    if result:
        return result

    result = _detect_from_file_content(ctx.files)
    if result:
        return result

    return _detect_from_root_files(ctx.root)


def _detect_node_framework(root: Path) -> str:
    """Check package.json for Node frameworks."""
    pkg_json = root / "package.json"
    if not pkg_json.exists():
        return ""
    pkg = read_file_safe(pkg_json) or ""
    _NODE_MARKERS = [('"express"', "express"), ('"@nestjs/core"', "nestjs")]
    for marker, framework in _NODE_MARKERS:
        if marker in pkg:
            return framework
    return ""


# Extended file-content detectors including ASP.NET
_ALL_FILE_DETECTORS: list[tuple[set[str] | None, str | None, str, str]] = [
    ({"app.py", "__init__.py"}, None, "from flask", "flask"),
    ({"app.py", "__init__.py", "main.py"}, None, "from fastapi", "fastapi"),
    ({"app.py", "__init__.py", "main.py"}, None, "import fastapi", "fastapi"),
    ({"pom.xml", "build.gradle", "build.gradle.kts"}, None, "spring-boot", "spring"),
    (None, ".csproj", "Microsoft.AspNetCore", "aspnet"),
]


def _detect_from_file_content(files: list[Path]) -> str:
    """Scan files matching filename or suffix patterns."""
    for f in files:
        for name_set, suffix, marker, framework in _ALL_FILE_DETECTORS:
            matched = (name_set and f.name in name_set) or (suffix and f.suffix == suffix)
            if matched:
                content = read_file_safe(f)
                if content and marker in content:
                    return framework
    return ""


def _detect_from_root_files(root: Path) -> str:
    """Check root-level config files for framework markers."""
    for fname, marker, framework in _ROOT_FILE_DETECTORS:
        fpath = root / fname
        if fpath.exists():
            content = read_file_safe(fpath) or ""
            if marker in content.lower():
                return framework
    return ""


# --- Express.js ---

_EXPRESS_ROUTE_RE = re.compile(
    r"""(?:app|router)\.(get|post|put|delete|patch|all|use)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)


def _extract_express_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Express.js routes: app.get('/path'), router.post('/path')."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _EXPRESS_ROUTE_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "express")
            if method == "USE":
                method = "ALL"
            routes.append(SourceRoute(
                path=path, method=method, framework="express",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Next.js ---

def _extract_nextjs_routes_wrapper(content: str, file_path: str) -> list[SourceRoute]:
    """Placeholder — Next.js uses file-based routing, not content extraction."""
    return []


def _extract_nextjs_routes(files: list[Path], root: Path) -> list[SourceRoute]:
    """Extract Next.js API routes from pages/api/ or app/api/ directory structure."""
    routes = []
    for f in files:
        try:
            rel = f.relative_to(root)
        except ValueError:
            continue
        parts = rel.parts

        # pages/api/... or src/pages/api/...
        api_idx = _find_api_index(parts)
        if api_idx < 0:
            continue

        # Build route path from file structure
        route_parts = parts[api_idx:]
        path = "/" + "/".join(route_parts)

        # Remove file extension
        path = re.sub(r"\.(ts|tsx|js|jsx)$", "", path)
        # Remove /index suffix
        path = re.sub(r"/index$", "", path) or "/"
        # Convert [param] to {param}
        path = re.sub(r"\[\.\.\.(\w+)]", r"{\1}", path)
        path = re.sub(r"\[(\w+)]", r"{\1}", path)

        routes.append(SourceRoute(
            path=path, method="ALL", framework="nextjs",
            file_path=str(f), route_type="rest",
        ))
    return routes


def _find_api_index(parts: tuple[str, ...]) -> int:
    """Find the index where 'api' starts in path parts (after pages/ or app/)."""
    for i, p in enumerate(parts):
        if p == "api" and i > 0 and parts[i - 1] in ("pages", "app", "src"):
            return i
        if i > 1 and p == "api" and parts[i - 2] == "src":
            return i
    return -1


# --- Django ---

_DJANGO_PATH_RE = re.compile(
    r"""path\s*\(\s*['"]([^'"]+)['"]""",
)


def _extract_django_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Django URL patterns: path('api/users/', ...)."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _DJANGO_PATH_RE.finditer(line):
            path = "/" + m.group(1).strip("/")
            path = _normalize_route_path(path, "django")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="django",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Flask ---

_FLASK_ROUTE_RE = re.compile(
    r"""@\w+\.(route|get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _extract_flask_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Flask routes: @app.route('/path'), @bp.get('/path')."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _FLASK_ROUTE_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "flask")
            if method == "ROUTE":
                method = "ALL"
            routes.append(SourceRoute(
                path=path, method=method, framework="flask",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Go ---

_GO_ROUTE_RE = re.compile(
    r"""(?:HandleFunc|Handle|Get|Post|Put|Delete|Patch|Route|GET|POST|PUT|DELETE|PATCH)\s*\(\s*['"]([^'"]+)['"]""",
)


def _extract_go_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Go routes: mux.HandleFunc, chi.Get, gin.GET, echo.GET."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _GO_ROUTE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "go")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="go",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Spring Boot ---

_SPRING_MAPPING_RE = re.compile(
    r"""@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
)


def _extract_spring_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Spring Boot routes: @GetMapping("/path"), @RequestMapping(value="/path")."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _SPRING_MAPPING_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "spring")
            method = "ALL"
            lower_line = line.lower()
            if "@getmapping" in lower_line:
                method = "GET"
            elif "@postmapping" in lower_line:
                method = "POST"
            elif "@putmapping" in lower_line:
                method = "PUT"
            elif "@deletemapping" in lower_line:
                method = "DELETE"
            elif "@patchmapping" in lower_line:
                method = "PATCH"
            routes.append(SourceRoute(
                path=path, method=method, framework="spring",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- FastAPI ---

_FASTAPI_ROUTE_RE = re.compile(
    r"""@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _extract_fastapi_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract FastAPI routes: @app.get("/path"), @router.post("/path")."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _FASTAPI_ROUTE_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "fastapi")
            routes.append(SourceRoute(
                path=path, method=method, framework="fastapi",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- ASP.NET Core ---

_ASPNET_ATTR_RE = re.compile(
    r"""\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']\s*\)]""",
)
_ASPNET_MAP_RE = re.compile(
    r"""Map(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']""",
)


def _extract_aspnet_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract ASP.NET Core routes: [HttpGet("path")], MapGet("/path", ...)."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _ASPNET_ATTR_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "aspnet")
            routes.append(SourceRoute(
                path=path, method=method, framework="aspnet",
                file_path=file_path, line_number=i, route_type="rest",
            ))
        for m in _ASPNET_MAP_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "aspnet")
            routes.append(SourceRoute(
                path=path, method=method, framework="aspnet",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- NestJS ---

_NESTJS_CONTROLLER_RE = re.compile(
    r"""@Controller\s*\(\s*["']([^"']+)["']\s*\)""",
)
_NESTJS_METHOD_RE = re.compile(
    r"""@(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']*?)["']\s*\)""",
)


def _extract_nestjs_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract NestJS routes: @Controller("base") + @Get("/path")."""
    routes = []
    controller_base = ""
    for i, line in enumerate(content.splitlines(), 1):
        cm = _NESTJS_CONTROLLER_RE.search(line)
        if cm:
            controller_base = cm.group(1)
            if not controller_base.startswith("/"):
                controller_base = "/" + controller_base
        for m in _NESTJS_METHOD_RE.finditer(line):
            method = m.group(1).upper()
            sub_path = m.group(2)
            full_path = controller_base
            if sub_path:
                full_path = controller_base.rstrip("/") + "/" + sub_path.lstrip("/")
            full_path = _normalize_route_path(full_path, "nestjs")
            routes.append(SourceRoute(
                path=full_path, method=method, framework="nestjs",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Ruby on Rails ---

_RAILS_ROUTE_RE = re.compile(
    r"""(?:get|post|put|patch|delete)\s+["']([^"']+)["']""",
)
_RAILS_RESOURCES_RE = re.compile(
    r"""resources?\s+:(\w+)""",
)


def _extract_rails_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Rails routes: get "/path", resources :users."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _RAILS_ROUTE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "rails")
            method = "ALL"
            lower_line = line.strip().lower()
            if lower_line.startswith("get "):
                method = "GET"
            elif lower_line.startswith("post "):
                method = "POST"
            elif lower_line.startswith("put "):
                method = "PUT"
            elif lower_line.startswith("patch "):
                method = "PATCH"
            elif lower_line.startswith("delete "):
                method = "DELETE"
            routes.append(SourceRoute(
                path=path, method=method, framework="rails",
                file_path=file_path, line_number=i, route_type="rest",
            ))
        for m in _RAILS_RESOURCES_RE.finditer(line):
            name = m.group(1)
            base_path = f"/{name}"
            routes.append(SourceRoute(
                path=base_path, method="ALL", framework="rails",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Laravel ---

_LARAVEL_ROUTE_RE = re.compile(
    r"""Route::(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_LARAVEL_RESOURCE_RE = re.compile(
    r"""Route::(?:apiResource|resource)\s*\(\s*["']([^"']+)["']""",
)


def _extract_laravel_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Laravel routes: Route::get("/path"), Route::apiResource("/path")."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _LARAVEL_ROUTE_RE.finditer(line):
            method = m.group(1).upper()
            path = _normalize_route_path(m.group(2), "laravel")
            routes.append(SourceRoute(
                path=path, method=method, framework="laravel",
                file_path=file_path, line_number=i, route_type="rest",
            ))
        for m in _LARAVEL_RESOURCE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "laravel")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="laravel",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Rust (Actix/Axum) ---

_RUST_ROUTE_RE = re.compile(
    r"""\.route\s*\(\s*["']([^"']+)["']""",
)
_RUST_WEB_RE = re.compile(
    r"""web::(get|post|put|delete|patch)\s*\(\s*\)\s*\.to\s*\(""",
)
_RUST_RESOURCE_RE = re.compile(
    r"""\.resource\s*\(\s*["']([^"']+)["']""",
)


def _extract_rust_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Rust routes: .route("/path", ...), web::get().to(handler)."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _RUST_ROUTE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "rust")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="rust",
                file_path=file_path, line_number=i, route_type="rest",
            ))
        for m in _RUST_RESOURCE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "rust")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="rust",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Phoenix (Elixir) ---

_PHOENIX_ROUTE_RE = re.compile(
    r"""(?:get|post|put|patch|delete)\s+["']([^"']+)["']""",
)
_PHOENIX_RESOURCES_RE = re.compile(
    r"""resources\s+["']([^"']+)["']""",
)


def _extract_phoenix_routes(content: str, file_path: str) -> list[SourceRoute]:
    """Extract Phoenix routes: get "/path", resources "/path"."""
    routes = []
    for i, line in enumerate(content.splitlines(), 1):
        for m in _PHOENIX_ROUTE_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "phoenix")
            method = "ALL"
            stripped = line.strip().lower()
            if stripped.startswith("get "):
                method = "GET"
            elif stripped.startswith("post "):
                method = "POST"
            elif stripped.startswith("put "):
                method = "PUT"
            elif stripped.startswith("patch "):
                method = "PATCH"
            elif stripped.startswith("delete "):
                method = "DELETE"
            routes.append(SourceRoute(
                path=path, method=method, framework="phoenix",
                file_path=file_path, line_number=i, route_type="rest",
            ))
        for m in _PHOENIX_RESOURCES_RE.finditer(line):
            path = _normalize_route_path(m.group(1), "phoenix")
            routes.append(SourceRoute(
                path=path, method="ALL", framework="phoenix",
                file_path=file_path, line_number=i, route_type="rest",
            ))
    return routes


# --- Extractor registry (after all extractors are defined) ---

_EXTRACTORS: dict[str, object] = {
    "express": _extract_express_routes,
    "nextjs": _extract_nextjs_routes_wrapper,
    "django": _extract_django_routes,
    "flask": _extract_flask_routes,
    "go": _extract_go_routes,
    "spring": _extract_spring_routes,
    "fastapi": _extract_fastapi_routes,
    "aspnet": _extract_aspnet_routes,
    "nestjs": _extract_nestjs_routes,
    "rails": _extract_rails_routes,
    "laravel": _extract_laravel_routes,
    "rust": _extract_rust_routes,
    "phoenix": _extract_phoenix_routes,
}


# --- GraphQL ---

_GQL_TYPE_RE = re.compile(
    r"""type\s+(Query|Mutation|Subscription)\s*\{([^}]*)""",
    re.MULTILINE | re.DOTALL,
)
_GQL_FIELD_RE = re.compile(r"""^\s*(\w+)\s*[:(]""", re.MULTILINE)


def _is_graphql_file(path: Path, content: str) -> bool:
    """Check if a file likely contains GraphQL schema definitions."""
    if path.suffix in (".graphql", ".gql"):
        return True
    if "type Query" in content or "type Mutation" in content:
        return True
    if "typeDefs" in content and ("gql`" in content or "gql(" in content):
        return True
    return False


def _extract_graphql_schema(
    content: str, file_path: str,
) -> tuple[list[str], list[str], list[str]]:
    """Extract GraphQL types, queries, mutations from schema definitions."""
    types: list[str] = []
    queries: list[str] = []
    mutations: list[str] = []

    for m in _GQL_TYPE_RE.finditer(content):
        type_name = m.group(1)
        body = m.group(2)
        fields = _GQL_FIELD_RE.findall(body)

        if type_name == "Query":
            queries.extend(fields)
        elif type_name == "Mutation":
            mutations.extend(fields)
        types.append(type_name)

    return types, queries, mutations


# --- OpenAPI ---

def _extract_openapi_spec(content: str) -> list[str]:
    """Extract paths from OpenAPI/Swagger JSON specs found in source."""
    try:
        spec = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    paths = list(spec.get("paths", {}).keys())
    base_path = spec.get("basePath", "")
    if base_path and base_path != "/":
        paths = [base_path + p for p in paths]
    return paths


# --- Utilities ---

def _normalize_route_path(path: str, framework: str) -> str:
    """Normalize framework-specific path params to standard {param} format."""
    if not path.startswith("/"):
        path = "/" + path
    if framework in ("express", "nestjs"):
        # :id -> {id}
        path = re.sub(r":(\w+)", r"{\1}", path)
    elif framework in ("django", "flask"):
        # <int:pk> -> {pk}, <str:slug> -> {slug}, <name> -> {name}
        path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", path)
    elif framework in ("rails", "phoenix"):
        # :id -> {id}
        path = re.sub(r":(\w+)", r"{\1}", path)
    elif framework in ("go", "spring", "fastapi", "aspnet", "laravel", "rust"):
        # {param} already standard
        pass
    return path


def format_source_analysis(result: SourceAnalysisResult) -> str:
    """Format source analysis as context for LLM and discovery."""
    parts = []
    if result.framework:
        parts.append(f"Framework: {result.framework}")
    if result.routes:
        parts.append("Source code routes:")
        for r in result.routes[:30]:
            parts.append(f"  {r.method} {r.path} ({r.framework}, {r.route_type})")
    if result.graphql_queries:
        parts.append("GraphQL queries: " + ", ".join(result.graphql_queries[:20]))
    if result.graphql_mutations:
        parts.append("GraphQL mutations: " + ", ".join(result.graphql_mutations[:20]))
    if result.openapi_paths:
        parts.append("OpenAPI paths: " + ", ".join(result.openapi_paths[:20]))
    return "\n".join(parts) if parts else ""
