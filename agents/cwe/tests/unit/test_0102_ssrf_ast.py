"""Feature 0102 — CWE-918 is owned by the AST tier on every file it parses, behind the
legacy ``server_ctx`` gate (LLD §8.5, §9.3, D10, D19; plan task 3.3; A40 (3)).

``check_injection`` resolves ``server_ctx`` once per file, as it does today, and its SSRF
check gains the consumer head: on a file ``owns()`` models, ``_ast_spans(…, _RULE_918,
server_ctx)`` decides every request flow and ``emit_for_line`` emits the reported ones at the
sink line with ``validation.ast``; a file the AST cannot model reaches the former body,
renamed ``_check_ssrf_regex`` and unchanged.

The gate is ``_RULE_918.gate`` (``FamilyRule.gate``, §5): with no server marker in a
browser-capable file, a sink whose GLUED callee key — the flow pass's ``Calls.key``, carried
as ``Flow.sink_key`` — is one of ``fetch``, ``get``, ``open``, ``do`` is no sink. The key is
never the callee's last word (A40 (3)): ``this.http.get(u)`` and ``fetch(u)`` are gated;
``httpGet(u)`` (key ``httpget``) and ``urlOpen(u)`` (key ``urlopen``, last word ``open``) are
not. ``map.get(k)`` never reaches the gate: a generic verb on a receiver with no HTTP-client
evidence is no request sink (A44 (1) (a)). ``httpGet`` is no request sink under the frozen lexicons (``httpget`` is
in no sink set), so the gate's reading of it is pinned on the rule itself; ``urlOpen`` is a
request sink and pins the same reading end to end.

Pinned elsewhere: one owner per check id per file (``test_0102_owner_disjoint``); the
identity and sink-line quote of every AST row (``test_0102_identity``); ``decide`` and its
labels (the shared suite).

RED until the head lands: the AST rows, the decline, ``_RULE_918``, ``Flow.sink_key`` and the
renamed body do not exist yet. A gated sink with no server marker reports nothing today (the
regex tier's gate) and must keep reporting nothing (the AST tier's); the unparseable copy's
row is regex behaviour today and must stay exactly so.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cwe_agent.skills import injection_check
from cwe_agent.skills.injection_check import check_injection
from tests import _ast_heads, _ast_v1
from tests._ast_heads import SSRF_ID

if TYPE_CHECKING:
    from shared.ast import Flow

DEFAULT_VALUE = "cwe_918_5.ts"  # t = req.query.url, reset only when empty; http.get(t) on line 5
WRONG_VARIABLE = "cwe_918_3.js"  # allowedHost() cleans req.query.host; fetch(target) on line 5
HOST_ALLOWLIST = "cwe_918_1_clean.js"  # early-return hostname allowlist; fetch(target) on line 7
BROKEN = _ast_heads.unparsed(DEFAULT_VALUE)

# A request value fetched on line 2 (SINK_LINE). BROWSER's signature carries no server marker
# (``_SERVER_CONTEXT``: no framework import, no ``(req,`` handler signature), so the file's
# ``server_ctx`` is False; SERVER's ``(req, res)`` handler signature makes it True.
BROWSER = "export async function load(ctx, req) {{\n  return {call};\n}}\n"
SERVER = "export async function handler(req, res) {{\n  return {call};\n}}\n"
SINK_LINE = 2
# Each snippet's call, by its stem, and the glued callee key the flow pass carries for its
# sink (A40 (3)): fetch, get and get are gated; urlopen (a request sink everywhere, last word
# open) is not.
CALLS = {
    "fetch": ("fetch(req.query.u)", "fetch"),
    "http_get": ("this.http.get(req.query.u)", "get"),
    "map_get": ("map.get(req.query.u)", "get"),
    "url_open": ("urlOpen(req.query.u)", "urlopen"),
}
GATED = ("fetch", "http_get")
# A44 (1) (a): ``map.get(req.query.u)`` is no request sink, so it carries no flow to gate.
FLOWING = (*GATED, "url_open")
SERVER_SINKS = ("fetch", "http_get")  # map.get in server code is no shape this file pins


def _browser(stem: str) -> str:
    """The file name of the snippet ``stem`` in a file with no server marker."""
    return f"browser_{stem}.js"


SNIPPETS = {
    **{_browser(stem): BROWSER.format(call=call) for stem, (call, _) in CALLS.items()},
    **{f"server_{stem}.js": SERVER.format(call=CALLS[stem][0]) for stem in SERVER_SINKS},
}
# (glued key, server_ctx, the gate keeps the flow): gated only without server context, and only
# for the four keys; httpget is httpGet(u)'s key, whose last word is get (A40 (3)).
GATE_TABLE = [
    *((key, False, False) for key in ("fetch", "get", "open", "do")),
    ("httpget", False, True),
    ("urlopen", False, True),
    ("fetch", True, True),
    ("httpget", True, True),
]


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """The named ``ast_v1`` files and the snippets, each AST-owned, and an unparseable copy
    of ``cwe_918_5.ts``."""
    root = _ast_v1.stage(request, (DEFAULT_VALUE, WRONG_VARIABLE, HOST_ALLOWLIST))
    for name, text in SNIPPETS.items():
        (root / name).write_text(text, encoding="utf-8")
    _ast_heads.stage_unparseable(root, _ast_v1.AST_V1 / DEFAULT_VALUE)
    return root


def _scan(root: Path) -> _ast_heads.Scan:
    return _ast_heads.scan(check_injection, root)


def _rows(root: Path, rel: str) -> list[tuple[int, str | None]]:
    return _ast_heads.rows_at(_scan(root), root, rel, SSRF_ID)


@cache
def _flows(path: Path) -> Sequence[Flow]:
    """The request flows the AST models in ``path`` (``owns`` → ``candidates``)."""
    from shared.ast import owns

    return owns(path).analysis().candidates("request")


def _external_sink_lines(path: Path) -> set[int]:
    """The sink lines of ``path``'s request flows with an external origin."""
    return {flow.sink_line for flow in _flows(path) for o in flow.origins if o.cls == "external"}


def test_default_value_idiom_is_an_ast_row_at_the_http_get_line(root: Path) -> None:
    assert _rows(root, DEFAULT_VALUE) == [(5, "ast")]


def test_sanitiser_on_another_variable_is_an_ast_row(root: Path) -> None:
    assert _rows(root, WRONG_VARIABLE) == [(5, "ast")]


def test_host_allowlist_guard_reports_nothing_and_declines(root: Path) -> None:
    """``ALLOWED_HOSTS.includes(new URL(target).hostname)`` is a ``host_allow`` guard on the
    fetched variable: ``decide`` declines, recorded once on the consumer's file (A30)."""
    assert _rows(root, HOST_ALLOWLIST) == []
    assert _ast_heads.declines_on(_scan(root), HOST_ALLOWLIST) == [
        f"ast_decline family=request file={HOST_ALLOWLIST} line=7 rule=guarded:host_allow "
        "origins=external:request"
    ]


@pytest.mark.parametrize("key", GATED)
def test_gated_key_reports_nothing_without_server_context(root: Path, key: str) -> None:
    """Scenario C3. The AST models the flow (an external origin at the sink), so the empty
    result is the gate's doing."""
    rel = _browser(key)
    assert SINK_LINE in _external_sink_lines(root / rel)
    assert _rows(root, rel) == []


@pytest.mark.parametrize("key", SERVER_SINKS)
def test_gated_key_is_an_ast_row_in_server_code(root: Path, key: str) -> None:
    assert _rows(root, f"server_{key}.js") == [(SINK_LINE, "ast")]


def test_glued_key_outside_the_gate_reports_without_server_context(root: Path) -> None:
    """A40 (3): ``urlOpen``'s glued key ``urlopen`` is not gated, though its last word is."""
    assert _rows(root, _browser("url_open")) == [(SINK_LINE, "ast")]


@pytest.mark.parametrize("stem", FLOWING, ids=list(map(_browser, FLOWING)))
def test_flow_carries_the_glued_callee_key(root: Path, stem: str) -> None:
    """``Flow.sink_key`` is ``Calls.key``: the callee's last identifier glued (L1 (a)). The
    shared suite's
    ``test_0102_finding.py::test_family_spans_hands_the_gate_server_ctx_and_each_flows_glued_key``
    is the key's primary pin; this one reads it off the snippets the gate tests here stand on."""
    keys = {flow.sink_key for flow in _flows(root / _browser(stem)) if flow.sink_line == SINK_LINE}
    assert keys == {CALLS[stem][1]}


def test_a_map_read_is_no_request_sink(root: Path) -> None:
    """A44 (1) (a): ``map.get(req.query.u)`` — a generic verb, a receiver with no HTTP-client
    concept, an argument that is no URL — is no request sink: no flow, no row."""
    assert (list(_flows(root / _browser("map_get"))), _rows(root, _browser("map_get"))) == ([], [])


@pytest.mark.parametrize(
    ("key", "server_ctx", "kept"), GATE_TABLE,
    ids=[f"{key}-{'server' if ctx else 'browser'}" for key, ctx, _ in GATE_TABLE])
def test_gate_reads_the_glued_key(root: Path, key: str, server_ctx: bool, kept: bool) -> None:
    """``_RULE_918.gate(flow, server_ctx)`` over one real flow carrying each key."""
    from cwe_agent.skills.injection_check import _RULE_918

    flow = replace(_flows(root / _browser("fetch"))[0], sink_key=key)
    assert _RULE_918.gate(flow, server_ctx) is kept


def test_only_the_unparseable_file_reaches_the_regex_body(root: Path) -> None:
    """Ownership is the parse outcome alone (D10): only the file with an ERROR node runs
    ``_check_ssrf_regex``."""
    reached = _ast_heads.reaching(
        check_injection, root, injection_check, "_check_ssrf_regex",
        Path,  # the body's first argument is the file itself
    )
    assert reached == {BROKEN}


def test_unparseable_file_keeps_its_regex_row(root: Path) -> None:
    """The regex tier's row on ``cwe_918_5.ts`` (line 5, measured before 0102), with no
    ``validation.ast``."""
    assert _rows(root, BROKEN) == [(5, "regex")]
