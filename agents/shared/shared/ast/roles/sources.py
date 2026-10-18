"""The source lexicons and the structural callee keys (feature 0102, LLD §8.2, §8.4, §8.5, §9.1;
D22, D23, W4, W9, A27, A28).

Mode (c) of §9.1: a source, carrier or receiver lexicon is a WORD set, matched on
``roles.words`` - ``SOURCE_WORDS`` on a chain's ROOT identifier only (W9 (b)), a CALL source by
its glued key against ``SOURCE_CALL_KEYS`` (W9 (a)). The structural callee lexicons the
§8.4 rules read (``ACCESSOR_WORDS``, ``HANDLER_REGISTRATION_WORDS``, ``ITERATION_WORDS``,
``OUTPUT_PARAM_WORDS``, ``MERGE_WORDS``) are sink-side: stored glued, matched by the glued key
(mode (a)). ``DEMOTED_WORDS`` is the lift test's record of every word deliberately left out
of every lexicon, each with its reason.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from shared.ast.profile import PROFILES
from shared.ast.roles.sinks import (
    COMMAND_BUILDER_WORDS,
    COMMAND_WEAK,
    EXIT_WORDS,
    REQUEST_SINK_NO_POSITIONAL,
    REQUEST_TERMINAL_WORDS,
    SINK_KEYS,
    SINK_WORDS,
)

__all__ = [
    "ACCESSOR_RECEIVER_WORDS",
    "ACCESSOR_WORDS",
    "ACCUMULATOR_KEYS",
    "CALLBACK_PAYLOAD_WORDS",
    "CONDITIONAL_SOURCE_ROOTS",
    "DEMOTED_WORDS",
    "EXACT_NON_STRONG",
    "HANDLER_REGISTRATION_WORDS",
    "ITERATION_WORDS",
    "MERGE_WORDS",
    "OUTPUT_PARAM_WORDS",
    "PARAM_ANNOTATION_WORDS",
    "PARAM_HINTS",
    "RECEIVER_PARAM_WORDS",
    "RESPONSE_WORDS",
    "ROUTE_WORDS",
    "SINK_SIDE_KEYS",
    "SOURCE_CALL_KEYS",
    "SOURCE_ROLES_BY_FAMILY",
    "SOURCE_WORDS",
    "TYPE_ANNOTATION_WORDS",
    "UPLOAD_WORDS",
]

# ── sources (§8.1, §8.2; D22) ────────────────────────────────────────────────

SOURCE_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    "request": frozenset({
        "request", "req", "query", "params", "param", "body", "form", "forms", "header",
        "headers", "cookie", "cookies", "payload", "input", "upload", "uploaded", "multipart",
        "formdata", "searchparams", "files", "matchinfo", "pathparams", "queryparams",
        "viewargs",
    }),
    "argv": frozenset({"argv"}),
    "stdin": frozenset({"stdin", "readline", "prompt", "input", "getpass"}),
    "network": frozenset({"recv", "recvfrom", "socket", "message", "msg", "frame", "packet"}),
    # recognised so it can be tallied; reports nowhere (D22)
    "env": frozenset({"environ", "getenv"}),
})
# W9 (b): a chain matches iff its root's word is the key and the next segment's word is a member
# key, whose value names the role (`process.env` -> env, `event.records` -> request). A root
# bound by an IMPORT (a module) is skipped by the flat SOURCE_WORDS test: `flask.request.args`.
_REQ = "request"
CONDITIONAL_SOURCE_ROOTS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    root: MappingProxyType(members)
    for root, members in {
        "ctx": dict.fromkeys(
            ("request", "req", "query", "params", "body", "headers", "cookies", "files"), _REQ),
        "context": dict.fromkeys(("request", "req", "query", "params", "body"), _REQ),
        "event": dict.fromkeys(
            ("body", "querystringparameters", "pathparameters", "headers", "multivalueheaders",
             "records", "data", "payload"), _REQ),
        "process": {"argv": "argv", "stdin": "stdin", "env": "env"},
        "sys": {"argv": "argv", "stdin": "stdin"},
        "deno": {"args": "argv", "env": "env", "stdin": "stdin"},
        "bun": {"argv": "argv", "env": "env", "stdin": "stdin"},
        "os": {"environ": "env", "getenv": "env"},
        "self": {"request": _REQ, "req": _REQ},
        "this": {"request": _REQ, "req": _REQ},
    }.items()
})
# D22: the external roles each family may report; `env` is in none (it is tallied).
SOURCE_ROLES_BY_FAMILY: Mapping[str, frozenset[str]] = MappingProxyType({
    "path": frozenset({"request", "network", "upload", "argv", "stdin", "param_hint"}),
    "request": frozenset({"request", "network", "upload"}),
    "command": frozenset({"request", "network", "upload", "argv", "stdin", "param_hint"}),
})

# ── parameters (§8.4: R-C, R-D, R-T; D23, W4) ────────────────────────────────

# R-T. The glued single-token spellings come first: `words` does NOT split an all-lowercase run,
# so `filename` -> ("filename",), and the split combinations only fire on camelCase/underscore
# forms. Lifted from the regex tier's _TAINTED_SOURCE (D23).
PARAM_HINTS = frozenset({
    frozenset({"filename"}), frozenset({"filepath"}), frozenset({"file", "name"}),
    frozenset({"file", "path"}), frozenset({"fname"}), frozenset({"uploaded", "file"}),
    frozenset({"upload", "file"}), frozenset({"user", "file"}), frozenset({"dest", "path"}),
    frozenset({"dest", "file"}),
})
# R-D: only in annotation / decorator / default-call position. `context` deliberately absent: Go
# `context.Context` is not input (R-U covers Gin/Echo contexts).
PARAM_ANNOTATION_WORDS = frozenset({
    "query", "param", "params", "body", "header", "headers", "cookie", "cookies", "form", "file",
    "files", "upload", "uploaded", "uploadfile", "path", "req", "request", "ip", "payload",
    "multipart", "json", "servlet", "pathvariable", "requestparam", "requestbody",
    "modelattribute",
})
# W4: a TYPE annotation is tested against this set; `&Path`, `File`, `*os.File`, `net.IP` are
# value types, not request carriers (decorators and default calls - `@PathVariable`,
# `Path(...)`, `File(...)` - keep the full set).
TYPE_ANNOTATION_WORDS = PARAM_ANNOTATION_WORDS - {"path", "file", "files", "ip"}
# R-D: an annotated parameter is external(upload), not external(request), when its annotation,
# decorator or default-call words hold one of these.
UPLOAD_WORDS = frozenset({"upload", "uploaded", "file", "files"})
# R-C: the receiver parameter names a handler's "first parameter" skips (Python `self` / `cls`).
RECEIVER_PARAM_WORDS = frozenset({"self", "cls"})
ROUTE_WORDS = frozenset({
    "route", "get", "post", "put", "patch", "delete", "head", "options", "api", "endpoint",
    "handler", "view", "controller", "action", "websocket", "message",
})
# R-A (A28 (1)): a callback PARAM hitting these is external(network); the callback's other
# PARAMs get R-C's external(request).
CALLBACK_PAYLOAD_WORDS = frozenset({
    "data", "payload", "message", "msg", "event", "evt", "body", "packet", "frame", "job",
    "task", "record",
})
# R-C: a handler PARAM hitting these is no source. "w" (Go http.ResponseWriter) is the ONE
# documented exception to the ^[a-z0-9]{2,32}$ entry shape (A27 (1)).
RESPONSE_WORDS = frozenset({
    "res", "response", "resp", "reply", "next", "cb", "callback", "done", "self", "cls",
    "socket", "ws", "writer", "w",
})

# ── structural callee keys (§8.2, §8.4: R-A, R-B, R-J, R-U, R-W; mode (a), glued) ──

HANDLER_REGISTRATION_WORDS = frozenset({
    "get", "post", "put", "patch", "delete", "all", "use", "route", "on", "once", "addlistener",
    "addeventlistener", "subscribe", "consume", "handle", "listen", "serve",
})
ITERATION_WORDS = frozenset({
    "then", "map", "foreach", "filter", "reduce", "flatmap", "find", "some", "every", "each",
    "foreachasync",
})
# R-B: the iteration keys whose callback receives the element as PARAM 1 (PARAM 0 accumulates).
ACCUMULATOR_KEYS = frozenset({"reduce"})
# D-D (Go/Java/Rust/PHP): R-U's accessor-style request APIs.
ACCESSOR_WORDS = frozenset({
    "query", "param", "params", "formvalue", "postform", "postformvalue", "getparameter",
    "getparametervalues", "getparametermap", "getheader", "getquery", "getcookies", "input",
    "formdata", "json", "body", "bind", "bindjson", "shouldbind", "shouldbindjson", "decode",
    "unmarshal", "cookie", "cookies", "header", "headers", "files", "file", "matchinfo",
    "pathparam", "queryparam", "vars", "form", "all", "route", "segment", "getinputstream",
    "getreader", "getparts", "getpart",
})
# R-U's receiver: a mode-(c) word set (annotation / decorator words of the receiver PARAM).
ACCESSOR_RECEIVER_WORDS = frozenset({
    "context", "ctx", "request", "req", "http", "servlet", "web", "handler", "conn", "session",
    "exchange",
})
# R-W (A28 (7): only on a profile with ``reference_args``, Go and Rust).
OUTPUT_PARAM_WORDS = frozenset({
    "bind", "bindjson", "shouldbind", "shouldbindjson", "decode", "unmarshal", "parse", "read",
    "scan", "fromreader", "fromstr",
})
# R-J (§8.2): the merge keys (A27 (6)).
MERGE_WORDS = frozenset({"assign", "merge", "extend", "defaults", "deepmerge"})

# ── derived once (W9 (a), A27 (2)) ───────────────────────────────────────────

# W9 (a), A27 (2): a CALL is a source by its glued key only when it is a READING function - the
# stdin, network and env words minus SINK_KEYS - with that set's role: input -> stdin,
# getenv -> env, recv -> network. A request word names an object or a field, never a reading
# function, and `socket` (a request sink key) drops out.
SOURCE_CALL_KEYS: Mapping[str, str] = MappingProxyType({
    key: role
    for role in ("stdin", "network", "env")
    for key in sorted(SOURCE_WORDS[role])
    if key not in SINK_KEYS
})
# The structural mode-(a) callee lexicons: sink-side, glued, yet none makes a CALL a sink.
_STRUCTURAL = (
    REQUEST_TERMINAL_WORDS, OUTPUT_PARAM_WORDS, EXIT_WORDS, REQUEST_SINK_NO_POSITIONAL,
    ACCESSOR_WORDS, HANDLER_REGISTRATION_WORDS, ITERATION_WORDS, MERGE_WORDS,
)
# L2: the keys R-N's COMMAND_STRONG prefix never promotes - every exact COMMAND_WEAK entry and
# every entry of a non-command sink-side lexicon, a builtin of another family included
# (`execute` stays weak: `db.execute(sql)` is no command sink without a strengthener).
EXACT_NON_STRONG = COMMAND_WEAK.union(
    *SINK_WORDS.values(), *_STRUCTURAL,
    (key for p in PROFILES.values() for key, b in p.builtin_sinks.items() if "command" not in b.families),
)
# The union of every mode-(a) lexicon - SINK_KEYS (each sink-making entry and every profile
# builtin key), the structural lexicons and the builder words - derived once; the glue test
# reads it (A27 (2)), SOURCE_CALL_KEYS does not.
SINK_SIDE_KEYS = SINK_KEYS.union(*_STRUCTURAL, COMMAND_BUILDER_WORDS)

# ── demotions (§9.1, A27 (3)) ────────────────────────────────────────────────

# Every word deliberately in no lexicon, with its reason; the lift test accepts a regex token
# only through a lexicon, this record or its stop list. Each is keyed as the lift test probes
# it (its glued form or one of its words, lowercase: BASE_DIR -> basedir) and enters NO role
# lexicon. CWE rules are framework-agnostic: a library or module name is never an entry.
_LIBRARY = "a library or module name: CWE rules are framework-agnostic (concepts + data flow)"
_CONFIG = "a configuration constant naming a base directory: a value, not an operation"
_JAVA_READ = (
    "a regex-alternation fragment of Files.read(String|AllBytes): the Java read reaches its "
    "path through the builtin pairs Paths.get / Path.of"
)
DEMOTED_WORDS: Mapping[str, str] = MappingProxyType({
    "user": (
        "a principal, not an input (0101); `userInput`/`user_file` still match through "
        "`input`/`file`"
    ),
    "args": "only under process/sys/deno roots; a bare `args` or `...args` parameter is not argv",
    "env": "recognised but never reports (D22)",
    "ioutil": _LIBRARY + " (Go io/ioutil; its ReadFile is the glued key `readfile`)",
    "httpx": _LIBRARY + " (its get/post are the request sink keys)",
    "requests": _LIBRARY + " (its get/post are the request sink keys)",
    "urllib": _LIBRARY + " (its urlopen is the request sink key `urlopen`)",
    "runtime": (
        "a regex-alternation fragment whose glued callee is already a key: "
        "Runtime.getRuntime().exec is the command sink `exec`"
    ),
    "paths": (
        "a regex-alternation fragment whose glued callee is already a key: Paths.get is the "
        "builtin pair `pathsget`"
    ),
    "allbytes": _JAVA_READ,
    "string": _JAVA_READ,
    "create": (
        "a builder token: URI.create, Object.create and os.Create share it, so it names no "
        "file operation"
    ),
    "true": "a syntax token: shell=True is read structurally (a KWARG `shell`, literal true)",
    "bin": "a path fragment of /bin/sh: R-M reads the interpreter's basename (SHELL_INTERPRETERS)",
    "new": "a syntax token: `new File(...)` is the CALL of its type, keyed by the type",
    "join": "a path builder: it passes origins through and is no sink (§9.1 SINK_WORDS)",
    "basedir": _CONFIG,
    "rootdir": _CONFIG,
    "dir": _CONFIG + " (PHP __DIR__)",
    "normpath": "a normalisation without containment proves nothing (B7): no sanitiser, no guard",
    "eval": (
        "not one of the three families: code evaluation is CWE-94/95, outside path, request "
        "and command"
    ),
})
