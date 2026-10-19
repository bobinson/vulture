"""The sink-side lexicons and the prefilter (feature 0102, LLD §8.5, §9.1; L1 (a), L2, L3, L7,
L8, R9, W5, W10, W15 d, A27).

Mode (a) of §9.1: a sink-side CALLEE lexicon is stored GLUED and matched by membership of the
callee's glued key (``roles.glue`` of its last identifier), one O(1) probe; a compound API name
needs its own glued entry (``readtostring``). ``COMMAND_STRONG`` is the one PREFIX match (R-N),
never over an exact ``COMMAND_WEAK`` or non-command entry (L2: ``execute`` stays weak). The
carrier and receiver sets here are mode (c) WORD sets, read through ``roles.words``.

``PREFILTER[family]`` is ONE compiled alternation of the glued keys whose presence must make
that family's parse happen, searched over the lower-cased, ``_``-free view of a file's text: it
may over-include a parse, never skip one (W15 d). ``model_needed`` is that one search, the
package ``shared.ast`` exports it (A27 (4)); ``needed_families`` asks several families of one
text over one view.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from itertools import accumulate
from types import MappingProxyType

from shared.ast._validate import SHELL_INTERPRETERS
from shared.ast.profile import PROFILES
from shared.ast.roles._words import words

__all__ = [
    "BROWSER_REQUEST_KEYS",
    "BUILDER_ARG_KEYS",
    "BUILTIN_KEYS",
    "CLIENT_WORDS",
    "COLLECTION_WORDS",
    "COMMAND_BUILDER_WORDS",
    "COMMAND_CARRIER_WORDS",
    "COMMAND_RECEIVER_WORDS",
    "COMMAND_STRONG",
    "COMMAND_WEAK",
    "DATA_STORE_WORDS",
    "EXIT_WORDS",
    "FLAG_LITERALS",
    "GENERIC_REQUEST_VERBS",
    "PATH_KWARGS",
    "PREFILTER",
    "PROCESS_WORDS",
    "REGEX_WORDS",
    "REQUEST_API_WORDS",
    "REQUEST_CARRIER_WORDS",
    "REQUEST_SINK_NO_POSITIONAL",
    "REQUEST_TERMINAL_WORDS",
    "REV9_GLUED_ADDITIONS",
    "SHELL_INTERPRETERS",
    "SHELL_KWARG",
    "SHELL_PREFIXES",
    "SINK_KEYS",
    "SINK_WORDS",
    "SYNC_SUFFIX",
    "TWO_PATH_SINKS",
    "URL_KWARGS",
    "URL_SHAPE_WORDS",
    "WRITE_SINKS",
    "command_lead",
    "model_needed",
    "needed_families",
    "path_sink_key",
]

# ── sink words (§9.1, revision 3 + revision 9) ───────────────────────────────

# Builders (join, resolve, normalize, abspath, realpath) are NOT sinks: they pass origins
# through; CWE-73 stays with the regex sibling. Nor is `replace` (R9: a string replace is no file
# operation - Python os.replace is the builtin pair key `osreplace`, §6.3).
_PATH_SINKS = frozenset({
    "open", "fopen", "freopen", "read", "readfile", "readfilesync", "readlines", "readall",
    "readtext", "readbytes", "write", "writefile", "writelines", "writetext", "writebytes",
    "append", "appendfile", "unlink", "remove", "rm", "rmdir", "rmtree", "rename", "stat",
    "lstat", "readdir", "listdir", "scandir", "opendir", "iterdir", "glob", "walk", "mkdir",
    "makedirs", "exists", "isfile", "isdir", "access", "truncate", "chmod", "chown", "symlink",
    "readlink", "utimes", "watch", "copy", "copyfile", "copytree", "move", "cp",
    "createreadstream", "createwritestream", "stream", "sendfile", "download", "attachment",
    "directory", "save", "load", "include", "require", "import", "extract", "extractall",
})
# `send` only with a KWARG/PAIR named url/host (§8.5), never bare; `open` only in
# browser_capable profiles (L8: Go os.Open is a path sink only); `urlopen` everywhere.
_REQUEST_SINKS = frozenset({
    "fetch", "get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen",
    "open", "http", "https", "http2", "axios", "got", "needle", "undici", "curl", "wget",
    "connect", "dial", "do", "ws", "websocket", "socket", "channel", "stream", "send",
})
# Revision 9 (L1 (a) consequence): sink-side glued keys the corpus forces that the revision-3
# entries reached only by word splitting, each merged into the named set below and naming the
# fixture or decision that forces it. Guard and sanitiser helpers get NO entry (P1).
REV9_GLUED_ADDITIONS: Mapping[tuple[str, str], frozenset[str]] = MappingProxyType({
    # cwe_22_rs_1, cwe_22_rs_2 (fs::read_to_string); §6.3 Rust (fs::remove_file)
    ("SINK_WORDS", "path"): frozenset({"readtostring", "removefile"}),
})
SINK_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    family: words | REV9_GLUED_ADDITIONS.get(("SINK_WORDS", family), frozenset())
    for family, words in (("path", _PATH_SINKS), ("request", _REQUEST_SINKS))
})
# A44 (1) (e): a synchronous twin is the file operation its stem names (`mkdirSync`, `rmSync`):
# a glued key `<stem>sync` is a path sink when `<stem>` is one - a structural suffix rule of
# the sink lookup (``path_sink_key``), never a per-name entry; `readfilesync`, the one entry
# that predates the rule, stays.
SYNC_SUFFIX = "sync"

# ── request: generic verbs and HTTP-client evidence (A44 (1) (a)) ────────────

# The request sink keys that are generic verbs: a collection, a cache, a cookie store or a
# router answers them as often as an HTTP client does, so each is a request sink only with
# HTTP-client evidence (``_calls``): a client concept in the receiver chain, a URL-shaped
# argument, or no receiver (a module's own function counts as none).
GENERIC_REQUEST_VERBS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request", "open", "connect",
    "do",
})
# The client / transport concept words a receiver chain shows an HTTP client by.
CLIENT_WORDS = frozenset({"client", "transport", "http", "https", "http2"})
# A URL-shaped NAME argument: its words carry one of these.
URL_SHAPE_WORDS = frozenset({"url", "uri", "endpoint", "href", "host", "link"})
# The last word of a collection construction's callee (`new Map()`, `new WeakSet()`, Java
# `new HashMap<>()`, Python `dict()`): a receiver bound to one is no client.
COLLECTION_WORDS = frozenset({"map", "set", "dict", "list", "array"})

# ── command: regex and data-store receivers, process evidence (A44 (1) (c)) ──

# A receiver whose words carry a data-store concept runs a statement, not a process
# (`db.exec(sql)`, Go `db.Exec`, `conn.exec_driver_sql`): no command key makes it a sink.
DATA_STORE_WORDS = frozenset({
    "db", "database", "sql", "statement", "stmt", "query", "cursor", "conn", "connection",
})
# A regex construction's callee chain carries one of these, by a word or glued (`new
# RegExp(...)` -> regexp, `re.compile`, `Pattern.compile`, Go `regexp.MustCompile`): a
# receiver bound to one, or to a regex literal, matches text and runs no command.
REGEX_WORDS = frozenset({"regexp", "regex", "pattern", "re"})
# R-N's prefix reaches a single-word identifier only (`execa`, `execvp`). A multi-word one
# (`execSync`, `runCommandWithTimeout`) reaches a command key only through leading words that
# glue to a COMMAND_STRONG key exactly AND one of these process concepts in its own words, its
# receiver chain or the module it is imported from (`child_process`): `executePollAction`,
# `ExecApprovalContainer` and `forkJoin` are no process.
PROCESS_WORDS = frozenset({"process", "subprocess", "child", "proc", "shell", "pty"})

# ── command (§8.5; R-L, R-M, R-N, R-V) ───────────────────────────────────────

# Glued; prefix-matched (R-N) unless the key is an exact COMMAND_WEAK / non-command entry (L2).
COMMAND_STRONG = frozenset({
    "exec", "spawn", "fork", "system", "popen", "checkoutput", "checkcall", "getoutput",
    "getstatusoutput", "createsubprocess", "shellexec", "passthru", "procopen", "execcommand",
    "runcommand", "runshell", "ptyspawn", "processbuilder", "startprocess",
})
# A sink only with a strengthener: KWARG `shell` literal true, or a COMMAND_RECEIVER_WORDS chain.
COMMAND_WEAK = frozenset({"run", "call", "start", "sh", "shell", "command", "cmd", "execute"})
COMMAND_RECEIVER_WORDS = frozenset({
    "subprocess", "child", "process", "proc", "os", "shell", "sh", "cmd", "command", "exec",
    "spawn", "system", "pty", "ssh", "client",
})
# R-V (L7): a builder-chain call on a COMMAND_CARRIER_WORDS receiver chain.
COMMAND_BUILDER_WORDS = frozenset({
    "arg", "args", "env", "spawn", "output", "status", "exec", "run", "start", "wait",
    "redirecterrorstream", "directory",
})
COMMAND_CARRIER_WORDS = frozenset({"command", "process", "builder", "cmd", "shell", "proc"})
# M4 literal values, compared lowercased. L3: R-M needs a SHELL_INTERPRETERS program (the wire
# vocabulary of ``_validate``, re-exported here, A10) and a later FLAG_LITERALS member.
FLAG_LITERALS = frozenset({"-c", "/c", "-command", "-e", "-exec", "--command", "-k", "/k"})
# W15 (a): the builder-chain calls whose arguments continue R-M's argument sequence, in chain
# order (`Command::new("sh").arg("-c").arg(x)`, `.args(["-c", x])`).
BUILDER_ARG_KEYS = frozenset({"arg", "args"})
# §8.5 command row: every positional argument is a sink argument when a KWARG of this name is the
# literal true (`subprocess.run(cmd, shell=True)`), or when the glued key starts with one of these.
SHELL_KWARG = "shell"
SHELL_PREFIXES = ("shell", "system")

# ── request (§8.5; R-V, W10) ─────────────────────────────────────────────────

REQUEST_TERMINAL_WORDS = frozenset({
    "send", "execute", "openconnection", "openstream", "connect", "do", "get", "post", "put",
    "patch", "delete", "fetch", "dial", "perform",
})
REQUEST_CARRIER_WORDS = frozenset({
    "url", "uri", "http", "https", "request", "client", "builder", "connection", "curl",
    "socket",
})
# §8.5 request row: builder-tail keys whose target lives in the receiver or the options, never
# in arg 0 (`res.send(x)`, `ws.send(x)` are response / socket echoes, not SSRF). A27 (6).
REQUEST_SINK_NO_POSITIONAL = frozenset({
    "send", "ws", "websocket", "socket", "channel", "stream", "execute", "perform",
})
# W10: the KWARG / OBJECT-literal PAIR names whose value is a request sink argument
# (`client.request("GET", url=t)`, `client.request({ url: t })`), glued.
URL_KWARGS = frozenset({
    "url", "uri", "href", "host", "hostname", "baseurl", "endpoint", "target", "address",
})
# L8: the bare keys that are request sinks only in a browser_capable profile (Go os.Open is a
# path sink only); `urlopen` is a distinct key and a request sink everywhere.
BROWSER_REQUEST_KEYS = frozenset({"open"})

# ── path argument positions (§8.5 path row; L9, W14, R10) ───────────────────

# R10: two-path operations take path_args "all" - the source AND the destination are paths.
TWO_PATH_SINKS = frozenset({
    "rename", "renamesync", "copy", "copyfile", "copyfilesync", "cp", "move", "mv", "symlink",
    "link", "linksync", "symlinksync",
})
# W14: a write-style key with exactly ONE positional argument has no path argument (that
# argument is the data: `w.Write(data)`, `f.write(s)`); with two or more, arg 0 is the path.
WRITE_SINKS = frozenset({"write", "writelines", "writetext", "writebytes", "append"})
# §8.5: the default path position (0,) is arg 0, or a KWARG of one of these names, glued.
PATH_KWARGS = frozenset({"path", "file", "filename", "src", "dest"})

# ── exits (W2: the one `exits(S)` predicate of §8.5 reads them) ─────────────

EXIT_WORDS = frozenset({"exit", "abort", "die", "fail", "panic", "halt", "terminate", "bail"})

# ── derived once (A27 (2)) ───────────────────────────────────────────────────

# A44 (1) (a): a receiver chain shows an HTTP client by a client concept or by a request sink
# key that names a request API rather than a verb (`axios`, `http`, `fetch`): derived from the
# request table, so no API name is entered twice.
REQUEST_API_WORDS = CLIENT_WORDS | (
    SINK_WORDS["request"] - GENERIC_REQUEST_VERBS - REQUEST_SINK_NO_POSITIONAL
)
# Every profile's builtin sink keys, an EMPTY family set included (C `read`, P4/R5).
BUILTIN_KEYS = frozenset(key for p in PROFILES.values() for key in p.builtin_sinks)
# The keys that make a CALL a sink - NOT every sink-side structural lexicon: SOURCE_CALL_KEYS is
# the reading words minus these (A27 (2)).
SINK_KEYS = frozenset().union(*SINK_WORDS.values(), COMMAND_STRONG, COMMAND_WEAK, BUILTIN_KEYS)

# ── the prefilter (§9.1 note 2, W15 d) ───────────────────────────────────────

# Each owning profile's builtin keys of a family, as the text spells them: a single key itself,
# a PAIR key by its qualifier (`Paths.get` -> `paths`), whose two parts the text never glues.
_BUILTIN_TERMS = frozenset(
    (family, sink.qualifier or key)
    for p in PROFILES.values()
    for key, sink in p.builtin_sinks.items()
    for family in sink.families & p.owned_families
)
# The glued keys whose presence must make each family's parse happen. `command` also carries
# the R-L template shell, the two characters $` - never a bare `$`, which as an end anchor
# would match every file and as a literal every PHP/JS variable (§9.1).
_FAMILY_TERMS: Mapping[str, frozenset[str]] = MappingProxyType({
    "path": SINK_WORDS["path"],
    "request": SINK_WORDS["request"] | REQUEST_TERMINAL_WORDS,
    "command": COMMAND_STRONG | COMMAND_WEAK | {"$`"},
})


def _alternation(terms: Iterable[str]) -> re.Pattern[str]:
    """One compiled alternation of literal ``terms``, each ``re.escape``d (no sink word brings
    a metacharacter), longest first so the pattern text is deterministic. A term holding
    another term (``readfile`` holds ``read``) can add no match to a search, so it is left
    out: the same answer from fewer alternatives tried at each position."""
    held = frozenset(terms)
    kept = sorted(filter(lambda t: not _holds_another(t, held), held), key=lambda t: (-len(t), t))
    return re.compile("|".join(map(re.escape, kept)))


def _holds_another(term: str, terms: frozenset[str]) -> bool:
    """``term`` contains some OTHER term of ``terms`` as a substring."""
    return any(other in term for other in terms if other != term)


PREFILTER: Mapping[str, re.Pattern[str]] = MappingProxyType({
    family: _alternation(terms | {term for fam, term in _BUILTIN_TERMS if fam == family})
    for family, terms in _FAMILY_TERMS.items()
})


def _glued_view(text: str) -> str:
    """The text as the prefilter reads it: lower-cased with ``_`` removed, so a glued key is a
    substring wherever its identifier is (``check_output(`` -> ``checkoutput(``). ``$`` stays:
    the R-L term needs it, and no other term holds one."""
    return text.lower().replace("_", "")


def path_sink_key(key: str) -> str:
    """The ``path`` sink key the glued callee ``key`` names (A44 (1) (e)): ``key`` itself, or
    the stem of a synchronous twin when that stem is a path sink key (``mkdirsync`` ->
    ``mkdir``); ``""`` for none (``closesync``: ``close`` is no path sink)."""
    if key in SINK_WORDS["path"]:
        return key
    stem = key.removesuffix(SYNC_SUFFIX)
    return stem if stem != key and stem in SINK_WORDS["path"] else ""


def command_lead(ident: str) -> bool:
    """A44 (1) (c): some leading run of ``ident``'s words glues to a ``COMMAND_STRONG`` key
    exactly (``execSync`` -> ``exec``, ``runCommandWithTimeout`` -> ``runcommand``), at most
    ``MAX_WORDS`` probes."""
    return any(lead in COMMAND_STRONG for lead in accumulate(words(ident)))


def needed_families(text: str, families: Iterable[str]) -> frozenset[str]:
    """The ``families`` whose sinks may exist in ``text`` (§5, §9.2, §9.3): its glued view is
    built once, then each family's ``PREFILTER`` searched over it, O(n) each. Nothing outlives
    the call: a consumer asking several families of one text asks once."""
    view = _glued_view(text)
    return frozenset(family for family in families if PREFILTER[family].search(view) is not None)


def model_needed(text: str, family: str) -> bool:
    """False only when no ``family`` sink can exist in ``text`` (§5, §9.2): ``needed_families``
    of that one family. Never word-bounded, so it may over-include a parse but never skip one."""
    return family in needed_families(text, (family,))
