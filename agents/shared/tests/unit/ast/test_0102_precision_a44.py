"""Feature 0102, A44 (1) (LLD §8.2, §8.4, §8.5, §9.1): the AST tier's precision on real code.

A skills-only run on real public code measured the AST tier's CWE-22/918/78 rows against the
regex tier's: most rows the AST tier added were false positives, from four sink-, source- and
guard-side shapes, and one recall gap. A44 (1) unfreezes the lexicons for these five items
only. Every change is a generic concept word or a structural rule — CWE rules are
framework-agnostic, so no helper, package, library or framework name is ever an entry:

(a) a request sink whose glued key is a generic verb (get, put, post, delete, ...) needs
    HTTP-client evidence — a client or transport concept word in the receiver chain, a
    URL-shaped argument (a scheme or ``://`` literal or template, or a name whose words carry
    url/uri/endpoint/href/host/link), or no receiver at all — and a receiver whose reaching
    Def is a collection construction (Map, Set, WeakMap, an object, dict or array literal) is
    never a request sink;
(b) a generic container word (``params`` and its kin) names a request source only as a member
    of a request-rooted chain (``req.params``) or as a parameter of a function in handler
    context (a handler registration, a route decorator, a ROUTE_WORDS name); a bare parameter
    elsewhere is ``unknown(param)``;
(c) a command key called on a receiver that is a regex (a literal, or a Def bound to one or to a
    regex construction) or whose words carry a data-store concept is no command sink; R-N's
    prefix match applies to single-word identifiers, and a multi-word one reaches a command key
    only through an exact first word plus process-concept evidence;
(d) a call STATEMENT dominating the sink in the same or an enclosing block, whose callee words
    carry a validation verb and a role concept word and which takes the flow's variable, guards
    that role; a call returning a containment-checked path that replaces the variable is a
    ``path_normalize`` sanitiser; a same-file function that tests its parameter with a guard
    role and exits early guards its callers' argument;
(e) a glued key ``<stem>sync`` is a path sink when ``<stem>`` is a path sink key — a structural
    suffix rule in the sink lookup, no per-name entries.

One test per item and side, through ``_analysis`` (real worker models; ``judge`` is the stub
rule and a recording context, so no ``server_ctx`` gate and no D25 hook). Each case is a
synthetic program or the ``ast_v1`` row that reproduces the shape in the corpus (identifiers
renamed; the held-out token rule, cwe ``test_0102_held_out.py``, reads those rows).

RED until the A44 (1) rules land: every negative of (a)-(d) is reported today, and every
positive of (e) is no sink today. The positives of (a)-(d) pass today: they pin the recall the
new restrictions must keep, each a shape the corpus or the rule's own wording keeps. The
negatives of (e) and its lexicon pin pass today too: they bound the suffix rule's reach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.unit.ast._analysis import (
    READ,
    SINK,
    SINK_P,
    Spec,
    call_line,
    entries,
    external,
    externals,
    flows_at_call,
    js_handler,
    judge,
    subject,
    unknown,
    verdicts_at,
)
from tests.unit.ast._audit import SANITIZED

if TYPE_CHECKING:
    from shared.ast.flow import Origin

pytestmark = pytest.mark.usefixtures("real_pool")

# A case is (subject, the sink CALL's head as ``call_head`` reads it) or, where the family
# varies, (subject, family, head); a (d) negative adds the verdict its decline starts with. A
# subject is an ``ast_v1`` stem or an inline ``(lang, source)`` program (``_analysis.subject``),
# dedented: its line 1 is its first line.
GUARDED_PREFIX = "guarded:"


def _reported(spec: Spec, family: str, head: str) -> bool:
    """``decide`` reports a ``family`` flow on the line of the sink CALL ``head``."""
    model = subject(spec)
    return call_line(model, head) in judge(model, family).reported


def _no_sink(spec: Spec, family: str, head: str) -> bool:
    """The CALL ``head`` is no ``family`` sink: no candidate's sink is on its line."""
    return not flows_at_call(subject(spec), family, head)


def _origins_at(spec: Spec, family: str, head: str) -> frozenset[Origin]:
    """The union of the origins of the ``family`` candidates on the line of the sink ``head``."""
    return frozenset().union(*(f.origins for f in flows_at_call(subject(spec), family, head)))


# ── (a) a generic verb needs HTTP-client evidence; a collection is never a client ──

_WEAKMAP = """
    const owners = new WeakMap();

    function handler(req, res) {
      res.json(owners.get(req.body.endpoint));
    }
"""
_CLASS_FIELD_MAP = """
    import express from "express";

    class Waiters {
      private pending = new Map<string, number>();

      cancel(req: express.Request): void {
        this.pending.delete(req.body.ticket);
      }
    }
"""
_COLLECTION_VERBS: dict[str, tuple[Spec, str]] = {
    # a Map Def: the key is URL-shaped, so only the collection rule refuses it
    "map_def_url_key": ("cwe_918_18_clean", "previewCache.get"),
    "set_def": ("cwe_918_19_clean", "liveSessions.delete"),
    "weakmap_def_url_key": (("js", _WEAKMAP), "owners.get"),
    "dict_literal_def_url_key": ("cwe_918_21_clean", "PREVIEWS.get"),
    # an imported receiver: no client concept in its chain, an argument that is not URL-shaped
    "member_chain_put": ("cwe_918_20_clean", "store.grants.put"),
    "member_chain_get": ("cwe_918_20_clean", "store.grants.get"),
    # a class field bound to a Map, read through `this`: either half refuses it
    "class_field_delete": (("ts", _CLASS_FIELD_MAP), "this.pending.delete"),
}

_SCHEME_TEMPLATE = js_handler("gateway.get(`https://${req.query.host}/status`);")
_BARE_VERB = """
    from httpx import get


    def view(request):
        target = request.args["t"]
        return get(target).text
"""
_CLIENT_VERBS: dict[str, tuple[Spec, str]] = {
    "client_receiver": ("cwe_918_22", "upstreamClient.get"),
    "client_chain": ("cwe_918_8", "apiClient.create({ timeout: 2000 }).get"),
    "transport_receiver": ("cwe_918_5", "http.get"),
    "url_shaped_name": ("cwe_918_23", "relay.post"),
    "scheme_template": (_SCHEME_TEMPLATE, "gateway.get"),
    "no_receiver": (("py", _BARE_VERB), "get"),
}


@pytest.mark.parametrize("case", list(_COLLECTION_VERBS))
def test_a_collection_verb_is_no_request_sink(case: str) -> None:
    """(a) negative: a generic verb with no HTTP-client evidence, or on a receiver bound to a
    collection construction, is no request sink — no ``request`` candidate at all."""
    spec, head = _COLLECTION_VERBS[case]
    assert _no_sink(spec, "request", head), f"{head} is still a request sink"


@pytest.mark.parametrize("case", list(_CLIENT_VERBS))
def test_an_http_client_verb_stays_a_request_sink(case: str) -> None:
    """(a) positive: a generic verb with HTTP-client evidence still reports a request value."""
    spec, head = _CLIENT_VERBS[case]
    assert _reported(spec, "request", head), f"{head} is no longer reported"


# ── (b) a container word is a request source only in a request chain or a handler ──

_PAYLOAD_HELPER = """
    function storeBlob(payload) {
      fs.writeFile(payload.target, payload.bytes, () => {});
    }
"""
_INPUT_HELPER = """
    export async function relayUpdate(input: Update): Promise<void> {
      await apiClient.post(input.webhookUrl, input.body);
    }
"""
_CONTAINER_PARAMS: dict[str, tuple[Spec, str, str]] = {
    # `params` is the first parameter: no R-C route by a request-named first parameter either
    "params_to_path": ("cwe_22_56_clean", "path", "fs.writeFile"),
    "params_second_to_request": ("cwe_918_24_clean", "request", "apiClient.post"),
    "params_to_command": ("cwe_78_19_clean", "command", "cp.spawn"),
    "payload_to_path": (("js", _PAYLOAD_HELPER), "path", "fs.writeFile"),
    "input_to_request": (("ts", _INPUT_HELPER), "request", "apiClient.post"),
}

_REGISTERED_CALLBACK = """
    router.post("/sync", (params, res) => {
      fs.readFile(params.file, () => {});
    });
"""
_ROUTE_DECORATED = """
    @app.route("/export")
    def export(params):
        return open(params["name"])
"""
_HANDLER_PARAMS: dict[str, tuple[Spec, str, str]] = {
    "request_rooted_chain": ("cwe_22_58", "path", "fs.readFile"),
    # the parameter is typed Request in a handler factory: no registration in the file
    "typed_request_factory": ("cwe_22_57", "path", "res.sendFile"),
    "route_word_function_name": ("cwe_22_27", "path", "fs.promises.readFile"),
    "registered_callback": (("js", _REGISTERED_CALLBACK), "path", "fs.readFile"),
    "route_decorator": (("py", _ROUTE_DECORATED), "path", "open"),
}


@pytest.mark.parametrize("case", list(_CONTAINER_PARAMS))
def test_a_container_parameter_outside_handler_context_is_unknown_param(case: str) -> None:
    """(b) negative: the sink stays a sink, but the parameter it reads is ``unknown(param)``,
    never ``external(request)``: no external origin reaches it, so ``decide`` reports nothing."""
    spec, family, head = _CONTAINER_PARAMS[case]
    origins = _origins_at(spec, family, head)
    assert (externals(origins), unknown("param") in origins) == (frozenset(), True)
    assert not _reported(spec, family, head)


@pytest.mark.parametrize("case", list(_HANDLER_PARAMS))
def test_a_container_in_a_request_chain_or_handler_stays_a_request_source(case: str) -> None:
    """(b) positive: ``req.params`` and a container parameter of a handler stay requests."""
    spec, family, head = _HANDLER_PARAMS[case]
    assert external("request") in _origins_at(spec, family, head)
    assert _reported(spec, family, head)


# ── (c) a regex, a data store or a multi-word exec name is no process ──

_CONNECTION_SQL = """
    from flask import request


    def purge(conn):
        owner = request.args["owner"]
        conn.exec_driver_sql("DELETE FROM drafts WHERE owner = '%s'" % owner)
"""
_MULTI_WORD_FORK = """
    import { forkMerge } from "./streams";

    export function handler(req: any): void {
      forkMerge(req.body.sources);
    }
"""
_NOT_A_PROCESS: dict[str, tuple[Spec, str]] = {
    "regex_literal_def": ("cwe_78_20_clean", "versionPattern.exec"),
    "regex_construction_def": ("cwe_78_21_clean", "tagMatcher.exec"),
    "regex_literal_receiver": ("cwe_78_22_clean", "/^v(\\d+)$/.exec"),
    "database_receiver": ("cwe_78_23_clean", "db.exec"),
    "go_database_receiver": ("cwe_78_go_3_clean", "db.Exec"),
    "connection_receiver": (("py", _CONNECTION_SQL), "conn.exec_driver_sql"),
    "execute_helper": ("cwe_78_24_clean", "executeTallyAction"),
    "exec_view_name": ("cwe_78_25_clean", "new ExecReviewPanel"),
    "fork_helper": (("ts", _MULTI_WORD_FORK), "forkMerge"),
}

_SPAWN_SYNC = """
    const childProcess = require("child_process");

    function handler(req, res) {
      childProcess.spawnSync("sh", ["-c", req.query.cmd]);
    }
"""
_CHECK_OUTPUT = """
    import subprocess


    def view(request):
        return subprocess.check_output(request.args["cmd"], shell=True)
"""
_REGEX_BESIDE_PROCESS = """
    const cp = require("child_process");
    const namePattern = /^[a-z]+$/;

    function handler(req, res) {
      namePattern.exec(req.query.dir);
      cp.exec("ls " + req.query.dir);
    }
"""
_PROCESS_CALLS: dict[str, tuple[Spec, str]] = {
    "single_word_member": ("cwe_78_1", "cp.exec"),
    "imported_sync_twin": ("cwe_78_6", "execSync"),
    "process_receiver_sync_twin": (("js", _SPAWN_SYNC), "childProcess.spawnSync"),
    "exact_glued_key": (("py", _CHECK_OUTPUT), "subprocess.check_output"),
    "beside_a_regex_exec": (("js", _REGEX_BESIDE_PROCESS), "cp.exec"),
}


@pytest.mark.parametrize("case", list(_NOT_A_PROCESS))
def test_a_regex_data_store_or_multi_word_exec_is_no_command_sink(case: str) -> None:
    """(c) negative: no ``command`` candidate on the line of the look-alike."""
    spec, head = _NOT_A_PROCESS[case]
    assert _no_sink(spec, "command", head), f"{head} is still a command sink"


@pytest.mark.parametrize("case", list(_PROCESS_CALLS))
def test_a_process_call_stays_a_command_sink(case: str) -> None:
    """(c) positive: a single-word command key, a multi-word one with process-concept evidence
    and an exact glued command key still report a request value."""
    spec, head = _PROCESS_CALLS[case]
    assert _reported(spec, "command", head), f"{head} is no longer reported"


# ── (d) statement-level validation calls, containment results, same-file helpers ──

_HOST_ASSERT = js_handler("const target = req.query.url;", "assertAllowedHost(target);",
                          "fetch(target);")
_COMMAND_VERIFY = """
    const cp = require("child_process");

    function handler(req, res) {
      const cmd = req.query.cmd;
      verifyShellArg(cmd);
      cp.exec(cmd);
    }
"""
_GUARDED_SINKS: dict[str, tuple[Spec, str, str, str]] = {
    "assert_in_the_same_block": ("cwe_22_59_clean", "path", "fs.readFile", GUARDED_PREFIX),
    "ensure_in_an_enclosing_block": ("cwe_22_60_clean", "path", "open", GUARDED_PREFIX),
    "containment_result": ("cwe_22_61_clean", "path", "fs.promises.readFile", SANITIZED),
    "same_file_helper": ("cwe_22_62_clean", "path", "fs.readFile", GUARDED_PREFIX),
    "host_role": (_HOST_ASSERT, "request", "fetch", GUARDED_PREFIX),
    "command_role": (("js", _COMMAND_VERIFY), "command", "cp.exec", GUARDED_PREFIX),
}

_INSIDE = "assertInsideRoot"
_LOGGING_HELPER = """
    function note(entry) {
      if (!entry.startsWith("/srv/")) {
        console.warn("outside");
      }
    }

    function handler(req, res) {
      const p = req.query.f;
      note(p);
      fs.readFileSync(p);
    }
"""
_UNGUARDED_SINKS: dict[str, tuple[Spec, str]] = {
    "check_after_the_sink": (js_handler(READ, SINK_P, f'{_INSIDE}(p, "/srv");'), SINK),
    "check_of_another_variable": (
        js_handler(READ, "const q = req.query.g;", f'{_INSIDE}(q, "/srv");', SINK_P), SINK,
    ),
    "check_of_another_role": (js_handler(READ, "assertAllowedHost(p);", SINK_P), SINK),
    "check_in_a_sibling_block": (
        js_handler(READ, f'if (req.query.strict) {{ {_INSIDE}(p, "/srv"); }}', SINK_P), SINK,
    ),
    "verb_without_a_role_word": (js_handler(READ, "verify(p);", SINK_P), SINK),
    "helper_that_does_not_exit": (("js", _LOGGING_HELPER), SINK),
    # a forward-slash blocklist on the else branch: a backslash still traverses
    "slash_blocklist": ("cwe_22_57", "res.sendFile"),
}


@pytest.mark.parametrize("case", list(_GUARDED_SINKS))
def test_a_dominating_validation_call_or_containment_result_declines(case: str) -> None:
    """(d) negative: ``decide`` declines the sink — ``guarded:`` + a covering role for a
    validation call or a same-file helper, ``sanitized:path_normalize`` for a containment
    result — instead of reporting it."""
    spec, family, head, verdict = _GUARDED_SINKS[case]
    found = verdicts_at(subject(spec), family, head)
    assert found.startswith(verdict), f"{head}: {found}"


@pytest.mark.parametrize("case", list(_UNGUARDED_SINKS))
def test_a_call_that_does_not_guard_the_flow_leaves_it_reported(case: str) -> None:
    """(d) positive: a call after the sink, on another variable, of another role, in a sibling
    block or with no role concept word, and a helper that does not exit, guard nothing."""
    spec, head = _UNGUARDED_SINKS[case]
    assert _reported(spec, "path", head), f"{head} is no longer reported"


# ── (e) a synchronous twin of a path sink key is a path sink ──

_SYNC_STEMS = (
    "mkdir", "rm", "rmdir", "rename", "unlink", "exists", "stat", "lstat", "readdir", "access",
    "chmod", "open", "truncate", "appendFile", "copyFile",
)
_SYNC_SINKS: dict[str, tuple[Spec, str]] = {
    "mkdir_row": ("cwe_22_63", "fs.mkdirSync"),
    "rename_row": ("cwe_22_64", "fs.renameSync"),
    "unlink_row": ("cwe_22_65", "fs.unlinkSync"),
    "rm_row": ("cwe_22_66", "fs.rmSync"),
    **{stem: (js_handler(READ, f"fs.{stem}Sync(p);"), f"fs.{stem}Sync") for stem in _SYNC_STEMS},
}
_NOT_PATH_SYNC = ("fs.closeSync", "fs.fsyncSync", "parser.parseSync")


@pytest.mark.parametrize("case", list(_SYNC_SINKS))
def test_a_sync_twin_of_a_path_sink_key_is_a_path_sink(case: str) -> None:
    """(e) positive: ``<stem>Sync`` reports a request value as ``<stem>`` does."""
    spec, head = _SYNC_SINKS[case]
    assert _reported(spec, "path", head), f"{head} is no path sink"


@pytest.mark.parametrize("head", _NOT_PATH_SYNC)
def test_a_sync_name_whose_stem_is_no_path_sink_key_is_no_path_sink(head: str) -> None:
    """(e) negative: the suffix rule needs the stem to be a path sink key itself."""
    assert _no_sink(js_handler(READ, f"{head}(p);"), "path", head)


def test_the_sync_rule_adds_no_per_name_entry() -> None:
    """(e): the rule is structural, in the sink lookup — the path sink words hold no glued
    ``*sync`` key but the one that predates it."""
    assert {key for key in entries("SINK_WORDS") if key.endswith("sync")} <= {"readfilesync"}
