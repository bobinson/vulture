"""Feature 0072 P3a — the route model: refutation at WIRING scope.

The dominant false-positive class is a framework establishing an invariant
outside the evidence window. A rule sees a query keyed on `req.body.ownerId`,
treats `req.body.*` as attacker-controlled, and reports an authorization bypass
— while auth middleware two files away has already overwritten that field from
the session token. The query is correctly scoped; the rule reported the
mitigation as the vulnerability.

Nothing at expression, function or file scope can see that. This module resolves
the wiring: which routes mount a handler, which middleware those routes carry,
and which request fields that middleware writes.

Two properties carry the design's weight:

  * EVERY mounting route must carry the mitigation, not any. A handler reachable
    through both a guarded and an unguarded route is NOT refuted — getting this
    backwards converts the gate into a false-negative generator.
  * Unresolvable is UNKNOWN, never empty-and-therefore-clean.

The contract (`RouteModel`) is framework-agnostic. `ExpressRouteModel` is the
first implementation; adding a family is a new implementation plus a fixture
pair, with no change to the obligation gate.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Protocol

__all__ = [
    "ExpressRouteModel",
    "Route",
    "RouteModel",
    "build_route_model",
]

# Files worth parsing for routes. Deliberately narrow: this runs once per repo.
_SOURCE_SUFFIXES = (".ts", ".js", ".mjs", ".tsx", ".jsx")

_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "coverage", "__pycache__",
    ".venv", "venv", "vendor", "third_party",
}

# app.get( / router.use( / app.all(
_MOUNT_RE = re.compile(
    r"\b(?:app|router|api|server)\s*\.\s*"
    r"(get|post|put|patch|delete|options|head|all|use)\s*\(",
    re.IGNORECASE,
)

# A middleware or handler reference inside a mount call: `foo()`, `a.b()`,
# `utils.asyncHandler(inner())` — we keep every identifier so an inner handler
# wrapped in a helper is still discoverable.
_IDENT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?=\()")

# `req.body.ownerId = ...`, `req.user = ...`
_WRITE_RE = re.compile(
    r"\breq\s*\.\s*((?:body|params|query|user|session)(?:\s*\.\s*[\w$]+)?)\s*=\s*([^\n;]+)"
)

# A value that comes from the server's own auth context rather than the client.
#
# The trailing `(?:[A-Z_]\w*)?\b` allows a CamelCase continuation so `tokenFrom`
# and `subjectOf` match, while `tokenizer` does NOT — after `token` the optional
# group cannot consume a lowercase `i`, so the word boundary fails.
#
# Conservatism matters in this direction specifically: a match here contributes
# to REFUTING a finding, so a spurious match is a false NEGATIVE — a real
# vulnerability silently dropped. That is the failure this feature must not
# create, so the vocabulary stays small and anchored rather than fuzzy.
#
# The base word is case-insensitive via a SCOPED flag; the continuation is not.
# A global re.IGNORECASE would make `[A-Z_]` match lowercase as well, so
# `tokenizer` would match `token` + `izer` — exactly the spurious refutation
# this is guarding against.
_SERVER_SOURCE_RE = re.compile(
    r"\b(?i:token|jwt|claim|subject|session|principal|authenticated"
    r"|decoded|currentuser)(?i:s)?(?:[A-Z_]\w*)?\b"
)

# `export const foo = ` / `export function foo(` / `function foo(` / `const foo =`
_DEF_RE = re.compile(
    r"\b(?:export\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)"
)


@dataclass(frozen=True)
class Route:
    """One mounted route. `middleware` is in mount order, prefix mounts first."""

    method: str
    pattern: str
    middleware: tuple[str, ...]
    handler: tuple[str, ...]      # every identifier in the handler position
    file: str
    line: int


class RouteModel(Protocol):
    """Framework-agnostic contract. See the LLD §5.8."""

    def routes(self) -> list[Route]: ...

    def resolve(self, file: str, line: int) -> list[Route]:
        """Every route that mounts the code at this location."""
        ...

    def writes(self, middleware: str) -> dict[str, str]:
        """request-field path -> provenance of the value written to it."""
        ...

    def field_is_server_derived(self, file: str, line: int, field_path: str) -> bool:
        """Whether EVERY route mounting this location writes `field_path` from a
        server-side source. False when unresolvable — never optimistic."""
        ...


def _balanced_call_args(text: str, open_paren: int) -> str:
    """Return the raw argument text of a call whose '(' is at `open_paren`."""
    depth = 0
    for i in range(open_paren, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
    return ""


def _split_top_level(args: str) -> list[str]:
    """Split a call's arguments on top-level commas."""
    out, depth, cur = [], 0, []
    quote = ""
    for c in args:
        if quote:
            cur.append(c)
            if c == quote:
                quote = ""
            continue
        if c in "\"'`":
            quote = c
            cur.append(c)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    if cur:
        out.append("".join(cur))
    return [a.strip() for a in out if a.strip()]


def _literal_path(arg: str) -> str | None:
    m = re.match(r"^['\"`]([^'\"`]*)['\"`]$", arg.strip())
    return m.group(1) if m else None


@dataclass
class ExpressRouteModel:
    """Express/Connect-style routing: `app.<verb>(path, ...mw, handler)` and
    `app.use(prefix, ...mw)` with prefix inheritance."""

    _routes: list[Route] = field(default_factory=list)
    _effects: dict[str, dict[str, str]] = field(default_factory=dict)
    _defs: dict[str, tuple[str, int, int]] = field(default_factory=dict)

    def __init__(self, routes=None, effects=None, defs=None):
        self._routes = list(routes or [])
        self._effects = dict(effects or {})
        self._defs = dict(defs or {})

    # ── contract ─────────────────────────────────────────────────────────
    def routes(self) -> list[Route]:
        return list(self._routes)

    def writes(self, middleware: str) -> dict[str, str]:
        return dict(self._effects.get(middleware, {}))

    def resolve(self, file: str, line: int) -> list[Route]:
        """Routes mounting the symbol whose definition spans (file, line).

        Resolution is symbol-based: find the enclosing definition, then every
        route whose handler position references that symbol. A finding outside
        any mounted symbol resolves to nothing, which the caller must treat as
        UNKNOWN.
        """
        symbol = self._enclosing_symbol(file, line)
        if symbol is None:
            return []
        return [r for r in self._routes if symbol in r.handler]

    def field_is_server_derived(self, file: str, line: int, field_path: str) -> bool:
        mounts = self.resolve(file, line)
        if not mounts:
            return False        # unresolvable is UNKNOWN, never clean
        for route in mounts:
            if not any(field_path in self.writes(mw) for mw in route.middleware):
                # One unguarded mount is enough to keep the finding.
                return False
        return True

    # ── internals ────────────────────────────────────────────────────────
    def _enclosing_symbol(self, file: str, line: int) -> str | None:
        best: tuple[str, int] | None = None
        for name, (f, start, end) in self._defs.items():
            if f != file or not (start <= line <= end):
                continue
            # Innermost definition wins.
            if best is None or start > best[1]:
                best = (name, start)
        return best[0] if best else None


def _scan_definitions(path: str, text: str) -> dict[str, tuple[str, int, int]]:
    """Map symbol -> (file, first_line, last_line).

    The span is approximate: from the definition line to the next top-level
    definition. Good enough to attribute a finding to its enclosing export, and
    deliberately conservative — an over-wide span can only cause a route to be
    considered, never skipped.
    """
    lines = text.splitlines()
    starts: list[tuple[str, int]] = []
    for i, ln in enumerate(lines, start=1):
        # TOP-LEVEL definitions only, i.e. no leading indentation.
        #
        # Without this, an inner `const cardId = ...` inside a handler body is
        # treated as a definition and truncates the enclosing function's span.
        # Measured on a real tree: `addWalletBalance` came out as lines 21-22
        # while its findings sit at line 27, so every handler resolved to zero
        # mounting routes and nothing could ever be refuted.
        if ln[:1] in (" ", "\t"):
            continue
        m = _DEF_RE.search(ln)
        if m:
            starts.append((m.group(1) or m.group(2), i))
    out: dict[str, tuple[str, int, int]] = {}
    for idx, (name, start) in enumerate(starts):
        end = starts[idx + 1][1] - 1 if idx + 1 < len(starts) else len(lines)
        out[name] = (path, start, end)
    return out


def _scan_middleware_effects(text: str, defs: dict) -> dict[str, dict[str, str]]:
    """Which request fields each definition writes, and from what."""
    effects: dict[str, dict[str, str]] = {}
    lines = text.splitlines()
    for name, (_f, start, end) in defs.items():
        body = "\n".join(lines[start - 1:end])
        for m in _WRITE_RE.finditer(body):
            field_path = re.sub(r"\s*", "", m.group(1))
            rhs = m.group(2)
            provenance = "token" if _SERVER_SOURCE_RE.search(rhs) else "unknown"
            if provenance == "token":
                effects.setdefault(name, {})[field_path] = f"server: {rhs.strip()[:60]}"
    return effects


def _parse_mount(
    path: str, text: str, m: "re.Match[str]",
) -> tuple[str, tuple[str, ...]] | Route | None:
    """One `app.<verb>(...)` call.

    Returns a `Route` for a verb mount, a `(prefix, middleware)` pair for an
    `app.use` prefix mount, or None when the call yields neither.
    """
    args_raw = _balanced_call_args(text, m.end() - 1)
    if not args_raw:
        return None
    args = _split_top_level(args_raw)
    if not args:
        return None

    verb = m.group(1).lower()
    first_path = _literal_path(args[0])
    rest = args[1:] if first_path is not None else args
    idents: list[tuple[str, ...]] = [tuple(_IDENT_RE.findall(a)) for a in rest]

    if verb == "use":
        # A prefix mount contributes middleware to everything beneath it.
        mws = tuple(i for group in idents for i in group)
        return (first_path, mws) if first_path is not None and mws else None

    if not idents:
        return None
    return Route(
        method=verb, pattern=first_path or "",
        middleware=tuple(i for group in idents[:-1] for i in group),
        handler=idents[-1], file=path,
        line=text[:m.start()].count("\n") + 1,
    )


def _inherit_prefixes(
    direct: list[Route], prefix_mw: list[tuple[str, tuple[str, ...]]],
) -> list[Route]:
    """Prepend each prefix mount's middleware to the routes beneath it."""
    out: list[Route] = []
    for r in direct:
        inherited = [mw for prefix, mws in prefix_mw
                     if r.pattern.startswith(prefix) for mw in mws]
        out.append(Route(
            method=r.method, pattern=r.pattern,
            middleware=tuple(inherited) + r.middleware,
            handler=r.handler, file=r.file, line=r.line,
        ))
    return out


def _scan_routes(path: str, text: str) -> list[Route]:
    """Extract mounts, applying prefix inheritance from `app.use(prefix, mw)`."""
    prefix_mw: list[tuple[str, tuple[str, ...]]] = []
    direct: list[Route] = []
    for m in _MOUNT_RE.finditer(text):
        parsed = _parse_mount(path, text, m)
        if parsed is None:
            continue
        if isinstance(parsed, Route):
            direct.append(parsed)
        else:
            prefix_mw.append(parsed)
    return _inherit_prefixes(direct, prefix_mw)


def build_route_model(root: str, *, max_files: int = 4000) -> ExpressRouteModel:
    """Build the route model for a source tree. One pass per repository.

    Cheap by construction: it reads only JS/TS sources and skips the usual
    vendored directories. The caller is expected to cache it — agents are
    separate processes, so an in-memory model would otherwise be rebuilt once
    per agent.
    """
    routes: list[Route] = []
    effects: dict[str, dict[str, str]] = {}
    defs: dict[str, tuple[str, int, int]] = {}
    seen = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(_SOURCE_SUFFIXES):
                continue
            seen += 1
            if seen > max_files:
                break
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            file_defs = _scan_definitions(path, text)
            defs.update(file_defs)
            effects.update(_scan_middleware_effects(text, file_defs))
            routes.extend(_scan_routes(path, text))

    return ExpressRouteModel(routes=routes, effects=effects, defs=defs)
