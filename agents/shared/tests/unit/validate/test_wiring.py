"""Feature 0072 P3a — the route model, and refutation at WIRING scope.

These are the LLD §8 wiring fixtures: identical handler bodies, different route
mounting, opposite correct verdicts. A rule that cannot tell them apart must
report both as candidates, never one as confirmed.
"""

from __future__ import annotations

import pytest

from shared.validate.wiring import ExpressRouteModel, build_route_model

# ── fixtures ──────────────────────────────────────────────────────────────

_MIDDLEWARE = """\
export const authContext = () => {
  return (req, res, next) => {
    req.body.ownerId = subjectOf(tokenFrom(req))
    next()
  }
}

export const noopLogger = () => {
  return (req, res, next) => { console.log(req.path); next() }
}
"""

# Identical bodies in both variants — only the mounting differs.
_HANDLER = """\
export function updateResource() {
  return async (req, res) => {
    await Model.update({ v: req.body.v }, { where: { ownerId: req.body.ownerId } })
    res.status(200).json({ ok: true })
  }
}
"""

_ROUTES_GUARDED = """\
import { authContext } from './middleware/auth'
import { updateResource } from './routes/handler'

export function build(app) {
  app.put('/resource/:id', authContext(), updateResource())
}
"""

_ROUTES_UNGUARDED = """\
import { updateResource } from './routes/handler'

export function build(app) {
  app.put('/resource/:id', updateResource())
}
"""

# One guarded mount AND one unguarded mount of the same handler.
_ROUTES_MIXED = """\
import { authContext } from './middleware/auth'
import { updateResource } from './routes/handler'

export function build(app) {
  app.put('/resource/:id', authContext(), updateResource())
  app.patch('/legacy/resource/:id', updateResource())
}
"""

_ROUTES_PREFIX = """\
import { authContext } from './middleware/auth'
import { updateResource } from './routes/handler'

export function build(app) {
  app.use('/resource', authContext())
  app.put('/resource/:id', updateResource())
}
"""


def _tree(tmp_path, routes_src: str):
    (tmp_path / "middleware").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "middleware" / "auth.ts").write_text(_MIDDLEWARE)
    (tmp_path / "routes" / "handler.ts").write_text(_HANDLER)
    (tmp_path / "routes.ts").write_text(routes_src)
    return str(tmp_path)


def _handler_line(tmp_path) -> tuple[str, int]:
    """The flagged line: the query keyed on req.body.ownerId."""
    path = str(tmp_path / "routes" / "handler.ts")
    for i, line in enumerate(_HANDLER.splitlines(), start=1):
        if "where:" in line:
            return path, i
    raise AssertionError("fixture changed")


# ── extraction ────────────────────────────────────────────────────────────

def test_extracts_verb_mounted_routes(tmp_path):
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    routes = m.routes()
    assert len(routes) == 1
    r = routes[0]
    assert r.method == "put"
    assert r.pattern == "/resource/:id"
    assert "authContext" in r.middleware
    assert "updateResource" in r.handler


def test_extracts_prefix_mounted_middleware(tmp_path):
    root = _tree(tmp_path, _ROUTES_PREFIX)
    m = build_route_model(root)
    r = next(x for x in m.routes() if x.method == "put")
    # app.use('/resource', authContext()) must be inherited by /resource/:id
    assert "authContext" in r.middleware, (
        f"prefix mount not inherited; middleware={r.middleware}")


def test_middleware_effect_table_records_what_a_middleware_writes(tmp_path):
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    writes = m.writes("authContext")
    assert "body.ownerId" in writes
    assert "token" in writes["body.ownerId"].lower()


def test_a_middleware_that_writes_nothing_has_no_effects(tmp_path):
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    assert m.writes("noopLogger") == {}


def test_resolve_maps_a_handler_line_to_its_mounting_routes(tmp_path):
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    path, line = _handler_line(tmp_path)
    routes = m.resolve(path, line)
    assert len(routes) == 1
    assert routes[0].pattern == "/resource/:id"


# ── the refutation decision ───────────────────────────────────────────────

def test_guarded_mount_refutes_the_field(tmp_path):
    """Every mounting route writes the field from the token, so a query keyed on
    it is correctly scoped — this is the false positive, refuted."""
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    path, line = _handler_line(tmp_path)
    assert m.field_is_server_derived(path, line, "body.ownerId") is True


def test_unguarded_mount_does_not_refute(tmp_path):
    """No middleware writes the field — the finding is real and must survive."""
    root = _tree(tmp_path, _ROUTES_UNGUARDED)
    m = build_route_model(root)
    path, line = _handler_line(tmp_path)
    assert m.field_is_server_derived(path, line, "body.ownerId") is False


def test_one_unguarded_mount_is_enough_to_keep_the_finding(tmp_path):
    """EVERY mounting route must carry the mitigation. Getting this backwards
    turns the gate into a false-negative generator."""
    root = _tree(tmp_path, _ROUTES_MIXED)
    m = build_route_model(root)
    path, line = _handler_line(tmp_path)
    routes = m.resolve(path, line)
    assert len(routes) == 2, "both mounts must be found"
    assert m.field_is_server_derived(path, line, "body.ownerId") is False, (
        "a handler reachable through one unguarded route is NOT refuted")


def test_unresolvable_handler_is_not_refuted(tmp_path):
    """No route found means UNKNOWN, never 'clean'."""
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    assert m.resolve(str(tmp_path / "middleware" / "auth.ts"), 3) == []
    assert m.field_is_server_derived(
        str(tmp_path / "middleware" / "auth.ts"), 3, "body.ownerId") is False


def test_a_different_field_is_not_refuted(tmp_path):
    """authContext writes body.ownerId; it says nothing about body.accountId."""
    root = _tree(tmp_path, _ROUTES_GUARDED)
    m = build_route_model(root)
    path, line = _handler_line(tmp_path)
    assert m.field_is_server_derived(path, line, "body.accountId") is False


# ── the contract is framework-agnostic ────────────────────────────────────

def test_a_stub_family_yields_unknown_rather_than_discharged():
    """Adding a family is additive: a model that resolves nothing must not
    silently discharge obligations."""
    class StubModel(ExpressRouteModel):
        def __init__(self):
            super().__init__(routes=[], effects={})

    m = StubModel()
    assert m.resolve("/any/file.ts", 1) == []
    assert m.field_is_server_derived("/any/file.ts", 1, "body.ownerId") is False


def test_build_route_model_on_a_tree_with_no_routes(tmp_path):
    (tmp_path / "x.py").write_text("print('no routes here')\n")
    m = build_route_model(str(tmp_path))
    assert m.routes() == []


# ── the provenance vocabulary must not over-match ─────────────────────────

@pytest.mark.parametrize("rhs,is_server_derived", [
    ("subjectOf(tokenFrom(req))", True),
    ("sessionUser.id", True),
    ("jwtPayload.sub", True),
    ("TokenFrom(r)", True),
    ("claims.sub", True),
    ("decodedClaims.sub", True),
    # These must NOT match. A spurious match here REFUTES a finding, so the
    # failure mode is a silently dropped vulnerability — the one direction this
    # feature must never introduce.
    ("tokenizer(x)", False),
    ("tokenise(x)", False),
    ("req.body.id", False),
    ("sanitize(x)", False),
    ("subjective(x)", False),
])
def test_server_source_vocabulary_is_precise(rhs, is_server_derived):
    from shared.validate.wiring import _SERVER_SOURCE_RE
    assert bool(_SERVER_SOURCE_RE.search(rhs)) is is_server_derived
