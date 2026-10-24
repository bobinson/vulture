"""Unit contract for the third re-audit of the guard-application rule (0097):
the principal outcome, the CSRF conjunct, and the comparand model."""

from __future__ import annotations

import pytest

from cwe_agent.skills._guard_application import (
    PRINCIPAL_PROVIDER,
    PRINCIPAL_RETURN,
    FileView,
    is_client_knowable,
    verified_conjunct,
)


def _view(src: str) -> FileView:
    lines = src.splitlines()
    return FileView(lines=lines, codes=tuple(lines), has_authz=lambda _t: False, role_patterns=())


@pytest.mark.parametrize("text", [
    "return User(id=claims['sub'])",
    "return AuthUser(sub)",
    "return new ClaimsPrincipal(identity);",
    "return models.User(id=uid)",
    "return new UserEntity({ id: sub });",
])
def test_a_constructor_named_as_a_principal_is_a_principal(text: str) -> None:
    assert PRINCIPAL_RETURN.search(text)


@pytest.mark.parametrize("text", [
    "return new UserPreview(body);",
    "return UserSummary(id=uid)",
    "return new UserPublicDto(await this.users.find(id));",
    "return new UserDetails(repo.find(id));",
    "return UserDto(user)",
])
def test_an_object_whose_name_only_contains_user_is_not_a_principal(text: str) -> None:
    assert not PRINCIPAL_RETURN.search(text)


@pytest.mark.parametrize("line", [
    "async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):",
    "def current_user(request):",
    "export async function getUser(req) {",
    "func (s *Server) authenticate(r *http.Request) (*Principal, error) {",
    "  async resolvePrincipal(req: Request) {",
    "  validate(req: Request) {",
    "  async validate(payload: JwtPayload) {",
])
def test_a_function_named_as_a_principal_provider_is_one(line: str) -> None:
    assert PRINCIPAL_PROVIDER.search(line)


@pytest.mark.parametrize("line", [
    "async def get_user_route(uid: int, request: Request, user=Depends(current_user)):",
    "async def preview(request: Request, user=Depends(current_user)):",
    "async create(@Req() req: Request, @Body() body: CreateUserDto) {",
    "public Object get(@PathVariable Long id, HttpServletRequest request) {",
])
def test_a_route_handler_is_not_a_principal_provider(line: str) -> None:
    assert not PRINCIPAL_PROVIDER.search(line)


@pytest.mark.parametrize("cond", [
    "if (req.headers['x-skip-auth'] === '1' && validateCsrfToken(req)) return next();",
    "if request.headers.get('X-Skip') == '1' and verify_csrf_token(request):",
    "if (req.query.debug === '1' && checkXsrfToken(req)) return next();",
])
def test_a_csrf_validator_is_not_a_verifying_conjunct(cond: str) -> None:
    assert not verified_conjunct(cond)


def test_a_credential_verifier_is_still_a_verifying_conjunct() -> None:
    assert verified_conjunct("if (req.headers['x-svc'] === 'a' && verifyToken(req)) return next();")


@pytest.mark.parametrize("comparand", [
    "req.cookies.internal) return next();",
    "req.query.admin) return next();",
    'request.args.get("role"):',
])
def test_a_comparand_that_is_a_request_read_is_client_knowable(comparand: str) -> None:
    assert is_client_knowable(comparand, _view(""))


@pytest.mark.parametrize("src, comparand", [
    ("define('DEBUG_KEY', 'letmein');", "DEBUG_KEY) {"),
    ("const BYPASS = 'on' as string;", "BYPASS) return next();"),
    ("class Mode(str, Enum):\n    BYPASS = \"bypass\"", "Mode.BYPASS.value:"),
    ("", "'yes' /* local only */) return next();"),
])
def test_a_literal_binding_shape_is_client_knowable(src: str, comparand: str) -> None:
    assert is_client_knowable(comparand, _view(src))


@pytest.mark.parametrize("src", [
    "let webhookSecret = 'dev-secret';\n"
    "if (process.env.NODE_ENV === 'production') webhookSecret = process.env.WEBHOOK_SECRET;",
    "let webhookSecret = 'changeme';\nloadSecrets().then((s) => { webhookSecret = s.svc; });",
    "let webhookSecret = 'local';\nconst argv = parseArgs(); webhookSecret = argv.secret;",
    'webhookSecret = "dev"\nif os.environ.get("S"): webhookSecret = os.environ["S"]',
    'var webhookSecret = "dev"\nfunc init() { if v := os.Getenv("S"); v != "" { webhookSecret = v } }',
    "let webhookSecret = 'dev';\nwebhookSecret += suffix;",
    "define('webhookSecret', getenv('WEBHOOK_SECRET'));",
])
def test_a_literal_default_reassigned_anywhere_is_not_client_knowable(src: str) -> None:
    assert not is_client_knowable("webhookSecret) return next();", _view(src))


def test_a_literal_reassigned_to_another_literal_stays_client_knowable() -> None:
    src = "let mode = 'off';\nif (dev) mode = 'on';"
    assert is_client_knowable("mode) return next();", _view(src))
