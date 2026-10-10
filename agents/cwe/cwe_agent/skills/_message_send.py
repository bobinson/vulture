"""Anonymous, caller-addressed message sends (CWE-799) — feature 0099.

A handler that lets a caller with no authenticated principal make the server
e-mail, text or otherwise message an address the CALLER chooses is a
mail-bombing / spam-relay vector. A quota keyed on the source address or the
recipient does not bound it, because both rotate; only a human-verification
step or an authenticated principal makes each send cost the attacker something.

The rule names no framework, library or platform. Every signal is read from
what an identifier MEANS (its camel/snake segments), how the recipient flows
inside the handler, and statement order:

1. a SEND call: the callee starts with a delivery verb and something on the
   call (callee or receiver) names a message;
2. its RECIPIENT argument: a recipient-named key, else the first argument whose
   name is contact-shaped;
3. CALLER-CHOSEN: walking assignments back from the recipient inside the
   handler (and one hop into a same-file helper it calls) reaches a read of
   request input — a ``body`` / ``query`` / ``form`` receiver or property, a
   ``params[...]`` subscript, an HTTP-method container;
4. NO PRINCIPAL and NO HUMAN CHECK that GATES the send: a mention only counts
   when it guards (a branch that exits, a bare assertion call) or wraps the
   handler (a decorator, annotation, enclosing container, or a registration
   line naming the handler). A mention that is only read never silences.

A quota anywhere in scope lowers the severity to medium; it never silences.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._guard_application import code_lines
from shared.tools.snippet import extract_snippet

CHECK_ID = "cwe.resource.anonymous_message_send"

logger = logging.getLogger(__name__)

_IDENT = re.compile(r"(?<![\w$])[$A-Za-z_][\w$]{0,80}+")
_SEGMENT = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

# ── send call ────────────────────────────────────────────────────────────────
# Prefilter AND locator: an optional single receiver, then a callee that starts
# with a delivery verb. Possessive and anchored by a lookbehind (ReDoS sweep).
SEND_CALL = re.compile(
    r"(?<![\w$.])(?:(?P<recv>[$A-Za-z_][\w$]{0,60}+)\s*+(?:\?\.|\.|::|->)\s*+)?"
    r"(?P<name>(?i:send|deliver|dispatch|notify)[\w$]{0,60}+)\s*+\("
)
_MESSAGE_PREFIXES = (
    "mail", "email", "sms", "text", "otp", "code", "link", "magic", "verif",
    "notif", "messag", "messenger", "invit", "passcode", "token", "reset",
    "confirm",
)
_VERB_PREFIXES = ("send", "deliver", "dispatch", "notify")
# A channel that is addressed by an e-mail address or a phone number. A generic
# `to` (a chat channel, a queue, a user id) is a recipient only when the call
# names one of these, or a contact-shaped name is on the recipient's chain.
_ADDRESS_CHANNEL = ("mail", "email", "smtp", "sms", "otp", "passcode", "magic")

# ── recipient ────────────────────────────────────────────────────────────────
_RECIPIENT_KEY = frozenset({"to", "recipient", "recipients", "rcpt", "email", "phone",
                            "msisdn", "mobile", "destination"})
_CONTACT = frozenset({"email", "mail", "phone", "msisdn", "mobile", "recipient", "rcpt"})
_SENDER_SIDE = frozenset({"from", "sender", "reply", "cc", "bcc", "admin", "support",
                          "noreply", "no"})
_KEYED_ARG = re.compile(r"^\s*+(?P<key>[$A-Za-z_][\w$]{0,60}+)\s*+(?::(?!:)|=(?![=>])|=>)\s*+(?P<val>.*)$",
                        re.DOTALL)

# ── caller-chosen ────────────────────────────────────────────────────────────
# Words that MEAN request input. Deliberately not `params`/`input`/`payload`/
# `args`/`dto` as bare receivers: those are ordinary parameter names (a mail
# template's `{ emailAddress } = params` is not request input).
INPUT_READ = re.compile(
    r"(?i:(?<![\w$])(?:body|query|form)\s*+(?:\?\.|\.|\[|->)"
    r"|(?:\?\.|\.|->)\s*+(?:body|query|form|params|json|cookies?)\b"
    r"|(?<![\w$])params\s*+\["
    r"|(?<![\w$])(?:form_?value|get_?param(?:eter)?s?|query_?param\w{0,20}+)\s*+\()"
    r"|\$_(?:POST|GET|REQUEST|COOKIE)\b|\.(?:POST|GET)\b"
)
_ASSIGN = re.compile(
    r"^(?P<lhs>[^=;]{1,200}?)\s*+(?::=|(?<![=!<>+\-*/%&|^?:])=)(?![=>~])\s*+(?P<rhs>.+)$"
)
_CALLED = re.compile(r"(?<![\w$.])(?P<name>[$A-Za-z_][\w$]{0,80}+)\s*+\(")
_MAX_HOPS = 6
# A parameter whose own annotation or type names request input (`@RequestBody`,
# `[FromForm]`, `= Form()`, a `query` type). Role words only: `params`/`input`
# are ordinary option-object names and stay out.
_ROLE = frozenset({"body", "form", "query"})
_ROLE_PAIRS = (("request", "param"), ("query", "param"))

# ── principal / human check / quota ──────────────────────────────────────────
_PRINCIPAL = frozenset({"session", "principal", "bearer", "jwt", "auth", "authenticate",
                        "authenticated", "authentication", "authorize", "authorized",
                        "signature", "hmac", "apikey"})
_PRINCIPAL_PAIRS = (("current", "user"), ("logged", "in"), ("signed", "in"),
                    ("login", "required"), ("api", "key"), ("access", "token"))
_VETO = frozenset({"anonymous", "optional", "skip", "bypass", "public"})
_REQUEST_USER = re.compile(r"(?<![\w$])(?:req|request|ctx|context)\s*+\.\s*+user\b")
_QUOTA = frozenset({"rate", "limit", "limiter", "ratelimit", "throttle", "throttled",
                    "throttler", "quota", "cooldown"})
_ASSERT_VERBS = frozenset({"require", "ensure", "assert", "authenticate", "authorize",
                           "verify", "check", "validate", "must"})
_ASSERTED_SUBJECT = frozenset({"user", "login", "signin", "account", "member"})
_BRANCH = re.compile(r"(?<![\w$])(?:if|unless|guard|when)\b")
_EXIT = re.compile(r"(?<![\w$])(?:return|throw|raise|abort|halt|exit|die)\b|\b40[13]\b")
_EXIT_SEGMENTS = frozenset({"unauthorized", "forbidden"})
_BARE_CALL = re.compile(r"^\s*+(?:await\s++|try\s++)?[$A-Za-z_][\w$.!:]{0,120}+\s*+(?:\(.*\))?\s*+;?\s*+$")
_DECORATOR = re.compile(r"^\s*+(?:@|\[|#\[)")

# ── function scope (generic) ─────────────────────────────────────────────────
_NOT_A_NAME = (r"(?!(?:if|for|while|switch|catch|return|await|new|throw|elif|else|when|"
               r"match|using|lock|foreach|with|unless|until|case|do|try|yield|echo|print|"
               r"defer|go|sizeof|typeof)\b)")
FUNC_HEADER = re.compile(
    r"(?<![\w$.])(?:function|def|func|fn|fun|sub)\b\s*+[$A-Za-z_(]"
    r"|^\s*+(?:[\w$<>\[\],.?*&:]{1,60}+\s++){1,6}+" + _NOT_A_NAME + r"[$A-Za-z_][\w$]{0,80}+\s*+\("
    r"|^\s*+" + _NOT_A_NAME + r"[$A-Za-z_][\w$]{0,80}+\s*+\([^;]{0,300}+\)\s*+(?::[^{;=]{0,120}+)?\{\s*+$"
)
_LINE_STARTS_NON_DECL = re.compile(r"^\s*+(?:return|throw|await|yield|new|else|echo|print|}|\)|\.)")
_ARROW = re.compile(r"=>")
_NAMED_ARROW = re.compile(r"(?<![=!<>])=(?![=>])[^=]*=>|['\"`]/")
_FUNC_NAME = re.compile(r"(?:function|def|func|fn|fun|sub)\s++(?:\([^)]{0,80}\)\s*+)?(?P<n>[$A-Za-z_][\w$]{0,80}+)"
                        r"|(?P<m>[$A-Za-z_][\w$]{0,80}+)\s*+\(")
_MAX_UP = 400
# Work bounds: a handler body is read at most _MAX_UP lines above the send, and
# at most _MAX_SENDS send calls are evaluated per file (a generated file with
# thousands of them would otherwise cost sends x lines x hops).
_MAX_SENDS = 200
# A line longer than this is not read as code: minified or generated text, and
# the shared string stripper is quadratic on a long line with an open quote.
_MAX_LINE_CHARS = 2000
_SNIPPET_SPAN = 37

_TITLE = "Anonymous caller chooses the recipient of a server-sent message"
_RECOMMENDATION = (
    "Gate the send on a server-verified human check (CAPTCHA / proof-of-work) or an "
    "authenticated principal; cap sends per flow and per recipient; keep the response "
    "identical whether or not the address is known; alert on send-rate spikes. Do not "
    "fix it by mailing only existing accounts: that breaks sign-up and enables enumeration."
)


@dataclass(frozen=True)
class _File:
    lines: Sequence[str]
    codes: tuple[str, ...]
    memo: dict = field(default_factory=dict)  # per-function results, computed once


def segments(ident: str) -> list[str]:
    """Lower-case camel/snake segments of one identifier."""
    return [s.lower() for s in _SEGMENT.findall(ident)]


def _idents(code: str) -> list[str]:
    return _IDENT.findall(code)


def _has_pair(segs: list[str], pair: tuple[str, ...]) -> bool:
    n = len(pair)
    return any(tuple(segs[i:i + n]) == pair for i in range(len(segs) - n + 1))


def is_principal(ident: str) -> bool:
    """An identifier that names an authenticated principal or credential
    check, and is not a negated / optional form of one."""
    segs = segments(ident)
    if _VETO.intersection(segs):
        return False
    return bool(_PRINCIPAL.intersection(segs)) or any(_has_pair(segs, p) for p in _PRINCIPAL_PAIRS)


def is_human_check(ident: str) -> bool:
    """An identifier that names a human-verification step."""
    low = ident.lower()
    segs = segments(ident)
    return ("captcha" in low or "siteverify" in low
            or _has_pair(segs, ("proof", "of", "work")) or _has_pair(segs, ("human", "verification")))


def _is_quota(ident: str) -> bool:
    return bool(_QUOTA.intersection(segments(ident)))


def _after_verb(word: str) -> str | None:
    """``word`` with its leading delivery verb removed, or None."""
    verb = next((v for v in _VERB_PREFIXES if word.startswith(v)), None)
    return None if verb is None else word[len(verb):]


def is_send_call(recv: str | None, name: str) -> bool:
    """Callee starts with a delivery verb and the call names a message."""
    words = segments(name)
    rest = _after_verb(words[0]) if words else None
    if rest is None:
        return False
    return any(w.startswith(_MESSAGE_PREFIXES) for w in (rest, *words[1:], *segments(recv or "")) if w)


# ── arguments ────────────────────────────────────────────────────────────────

def _balanced(text: str, depth: int, out: list[str]) -> int:
    """Append ``text`` to ``out`` up to the closing bracket; -1 once closed."""
    for ch in text:
        depth += (ch in "([{") - (ch in ")]}")
        if depth == 0:
            return -1
        out.append(ch)
    return depth


def _call_args(codes: Sequence[str], idx: int, col: int) -> str:
    """Text between the call's parentheses, balanced across at most 12 lines."""
    depth, out = 0, []
    for j in range(idx, min(len(codes), idx + 12)):
        depth = _balanced(codes[j][col:] if j == idx else codes[j], depth, out)
        if depth < 0:
            break
        out.append(" ")
    return "".join(out)[1:].strip()


def _split_top(text: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in text:
        depth += (ch in "([{") - (ch in ")]}")
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _keyed(arg: str) -> tuple[str, str] | None:
    m = _KEYED_ARG.match(arg)
    return (m.group("key"), m.group("val").strip()) if m else None


def _sender_side(segs: list[str]) -> bool:
    return bool(_SENDER_SIDE.intersection(segs))


def _is_object(arg: str) -> bool:
    return arg.startswith("{") and arg.endswith("}")


def _keyed_recipient(arg: str) -> str | None:
    key, val = _keyed(arg) or (arg, arg)
    segs = segments(key)
    return val if segs and segs[0] in _RECIPIENT_KEY and not _sender_side(segs) else None


def _recipient_by_key(args: list[str]) -> str | None:
    for arg in args:
        hit = _recipient_by_key(_split_top(arg[1:-1])) if _is_object(arg) else _keyed_recipient(arg)
        if hit:
            return hit
    return None


def _contact_shaped(expr: str) -> bool:
    return any(_CONTACT.intersection(s := segments(i)) and not _sender_side(s) for i in _idents(expr))


def recipient(args_text: str) -> str | None:
    """The recipient expression of a send call, or None."""
    args = _split_top(args_text)
    keyed = _recipient_by_key(args)
    if keyed is not None:
        return keyed
    return next((a for a in args
                 if _keyed(a) is None and not a.startswith("{") and _contact_shaped(a)), None)


# ── function scope ───────────────────────────────────────────────────────────

def _indent(code: str) -> int:
    return len(code) - len(code.lstrip())


def _is_header(code: str) -> bool:
    if not code.strip() or _LINE_STARTS_NON_DECL.match(code):
        return False
    if _ARROW.search(code):
        return bool(_NAMED_ARROW.search(code))
    return bool(FUNC_HEADER.search(code))


def _owner(codes: Sequence[str], j: int) -> int:
    """Nearest code line above ``j`` indented less than it (-1 at top)."""
    base = _indent(codes[j])
    lo = max(-1, j - _MAX_UP)
    return next((k for k in range(j - 1, lo, -1) if codes[k].strip() and _indent(codes[k]) < base), -1)


def _signature_start(codes: Sequence[str], k: int) -> int:
    """For `) {` / `{` closing a multi-line signature, the line that opened it."""
    if not codes[k].lstrip().startswith((")", "{")):
        return k
    base = _indent(codes[k])
    lo = max(-1, k - 40)
    return next((i for i in range(k - 1, lo, -1) if codes[i].strip() and _indent(codes[i]) <= base), k)


def function_header(codes: Sequence[str], j: int) -> int:
    """Line of the function enclosing line ``j``; -1 for top-level code."""
    k = j
    while (k := _owner(codes, k)) >= 0:
        k = _signature_start(codes, k)
        if _is_header(codes[k]):
            return k
    return -1


def _closes(code: str, base: int) -> bool:
    """A code line at or left of ``base`` that is not a signature tail."""
    return bool(code.strip()) and _indent(code) <= base and not code.lstrip().startswith((")", "{"))


def body_end(codes: Sequence[str], h: int) -> int:
    """Exclusive end of the body opened at header ``h``."""
    if h < 0:
        return len(codes)
    base, stop = _indent(codes[h]), min(len(codes), h + 2000)
    j = next((j for j in range(h + 1, stop) if _closes(codes[j], base)), stop)
    return j + (1 if j < stop and codes[j].lstrip().startswith(("}", "end")) else 0)


def _header_name(code: str) -> str | None:
    m = _FUNC_NAME.search(code)
    return (m.group("n") or m.group("m")) if m else None


def _function_index(codes: Sequence[str]) -> dict[str, int]:
    """Name -> header line, for one-hop resolution of same-file helpers."""
    index: dict[str, int] = {}
    for k, code in enumerate(codes):
        name = _header_name(code) if _is_header(code) else None
        if name:
            index.setdefault(name, k)
    return index


# ── gating ───────────────────────────────────────────────────────────────────

def _control_idents(code: str, pred: Callable[[str], bool]) -> bool:
    return any(pred(i) for i in _idents(code))


def _from_control(rhs: list[str], pred: Callable[[str], bool], bound: set[str]) -> bool:
    return any(pred(i) for i in rhs) or bool(bound.intersection(rhs))


def _binds_control(m: re.Match | None, pred: Callable[[str], bool], bound: set[str]) -> list[str]:
    """LHS names of an assignment whose RHS is a control or a bound name."""
    if not m or not _from_control(_idents(m.group("rhs")), pred, bound):
        return []
    return [i for i in _idents(m.group("lhs")) if not pred(i)]


def _gate_vars(codes: Sequence[str], lo: int, hi: int, pred: Callable[[str], bool]) -> set[str]:
    """Names bound (directly or transitively) to a control's result."""
    bound: set[str] = set()
    for k in range(lo, hi):
        bound.update(_binds_control(_ASSIGN.match(codes[k].strip()), pred, bound))
    return bound


def _exit_at(code: str) -> bool:
    return bool(_EXIT.search(code)) or any(_EXIT_SEGMENTS.intersection(segments(i)) for i in _idents(code))


def _exits(codes: Sequence[str], k: int, hi: int) -> bool:
    return any(_exit_at(codes[j]) for j in range(k, min(hi, k + 4)))


def _asserted(ident: str, pred: Callable[[str], bool]) -> bool:
    segs = segments(ident)
    if not _ASSERT_VERBS.intersection(segs):
        return False
    # `requireUser()` / `ensure_login()` assert a principal without naming one.
    return pred(ident) or (pred is is_principal and bool(_ASSERTED_SUBJECT.intersection(segs)))


def _asserts(code: str, pred: Callable[[str], bool]) -> bool:
    """A bare call statement whose callee is a control asserted by name."""
    if not _BARE_CALL.match(code):
        return False
    return any(_asserted(i, pred) for i in _idents(code.split("(")[0]))


def _branch_gate(codes: Sequence[str], k: int, hi: int, pred: Callable[[str], bool],
                 names: set[str]) -> bool:
    code = codes[k]
    mentions = _control_idents(code, pred) or bool(names.intersection(_idents(code)))
    return mentions and bool(_BRANCH.search(code)) and _exits(codes, k, hi)


def gated(codes: Sequence[str], lo: int, hi: int, pred: Callable[[str], bool]) -> bool:
    """A control matching ``pred`` guards lines ``lo..hi`` (branch-and-exit,
    or an asserting call)."""
    names = _gate_vars(codes, lo, hi, pred)
    return any(codes[k].strip() and (_asserts(codes[k], pred) or _branch_gate(codes, k, hi, pred, names))
               for k in range(lo, hi))


def _own_decorators(f: _File, h: int) -> list[str]:
    """Decorator / annotation / attribute lines directly above the header
    (blank lines between them allowed)."""
    out, k = [], h - 1
    while k >= 0 and (_DECORATOR.match(f.lines[k]) or not f.codes[k].strip()):
        out.append(f.codes[k])
        k -= 1
    return out


def _containers(f: _File, h: int) -> list[str]:
    """Enclosing container headers (a class, a module block) and their
    decorators."""
    out, k = [], h
    while (k := _owner(f.codes, k)) >= 0:
        k = _signature_start(f.codes, k)
        out.append(f.codes[k])
        out.extend(_decorators_above(f, k))
    return out


def _naming(f: _File, h: int, end: int, name: str | None) -> list[str]:
    """Lines outside the handler that name it (a wrapper, a registration)."""
    if not name:
        return []
    return [c for i, c in enumerate(f.codes)
            if (i < h or i >= end) and name in c and name in _idents(c)]


def _wrapper_lines(f: _File, h: int, end: int, name: str | None) -> list[str]:
    """Lines that wrap the handler: its header, its decorators, enclosing
    container headers, and lines outside it that name it."""
    if h < 0:
        return []
    return [f.codes[h], *_own_decorators(f, h), *_containers(f, h), *_naming(f, h, end, name)]


def _decorators_above(f: _File, k: int) -> list[str]:
    out, j = [], k - 1
    while j >= 0 and _DECORATOR.match(f.lines[j]):
        out.append(f.codes[j])
        j -= 1
    return out


def _wrapped(lines: list[str], pred: Callable[[str], bool]) -> bool:
    return any(_control_idents(c, pred) or (pred is is_principal and _REQUEST_USER.search(c))
               for c in lines)


# ── caller-chosen recipient ──────────────────────────────────────────────────

@dataclass
class _Chain:
    evidence: list[int]
    helpers: list[int]
    names: set[str] = field(default_factory=set)


def _signature(codes: Sequence[str], h: int) -> str:
    """Header text up to the body opener (at most 12 lines)."""
    out = []
    for j in range(h, min(len(codes), h + 12)):
        out.append(codes[j])
        if "{" in codes[j] or codes[j].rstrip().endswith(":"):
            break
    return " ".join(out)


def _is_role(chunk: str) -> bool:
    segs = [s for i in _idents(chunk) for s in segments(i)]
    return bool(_ROLE.intersection(segs)) or any(_has_pair(segs, p) for p in _ROLE_PAIRS)


def role_params(codes: Sequence[str], h: int) -> set[str]:
    """Parameters of the function at ``h`` declared as request input."""
    sig = _signature(codes, h) if h >= 0 else ""
    start = sig.find("(")
    if start < 0:
        return set()
    chunks = _split_top(_call_args([sig], 0, start))
    return {i for chunk in chunks if _is_role(chunk) for i in _idents(chunk)}


def _reads_input(text: str, roles: set[str]) -> bool:
    return bool(INPUT_READ.search(text) or roles.intersection(_idents(text)))


@dataclass
class _Walk:
    f: _File
    lo: int
    send: int
    index: dict[str, int]
    roles: set[str]
    names: set[str]
    chain: _Chain


def _assignments(f: _File, lo: int, hi: int) -> list[tuple[int, set[str], str]]:
    """(line, LHS names, RHS) for every assignment in ``lo..hi``, newest first;
    built once per scope."""
    key = ("assign", lo, hi)
    if key not in f.memo:
        found = ((k, _ASSIGN.match(f.codes[k].strip())) for k in range(hi - 1, lo - 1, -1))
        f.memo[key] = [(k, set(_idents(m.group("lhs"))), m.group("rhs")) for k, m in found if m]
    return f.memo[key]


def _step(w: _Walk, k: int, lhs: set[str], rhs: str) -> bool:
    """Follow the assignment on line ``k`` if it binds a chain name."""
    if not w.names.intersection(lhs):
        return False
    if _reads_input(rhs, w.roles) and k not in w.chain.evidence:
        w.chain.evidence.append(k)
    _follow_calls(w.f, rhs, k, w.index, w.chain)
    new = set(_idents(rhs)) - w.names
    w.names |= new
    return bool(new)


def _walk(f: _File, expr: str, lo: int, send: int, index: dict[str, int]) -> _Chain:
    """Assignments feeding ``expr`` within ``lo..send``; input reads found."""
    roles = role_params(f.codes, lo - 1)
    chain = _Chain(evidence=[send] if _reads_input(expr, roles) else [], helpers=[])
    _follow_calls(f, expr, send, index, chain)
    w = _Walk(f, lo, send, index, roles, set(_idents(expr)), chain)
    assigns = _assignments(f, lo, send)
    for _ in range(_MAX_HOPS):
        grew = [_step(w, k, lhs, rhs) for k, lhs, rhs in assigns]
        if not any(grew):
            break
    chain.names = w.names
    return chain


def _helper_end(codes: Sequence[str], h: int) -> int:
    return min(body_end(codes, h), h + 1 + _MAX_UP)


def _reads_in_helper(f: _File, h: int) -> bool:
    return any(INPUT_READ.search(c) for c in f.codes[h:_helper_end(f.codes, h)])


def _follow_calls(f: _File, text: str, at: int, index: dict[str, int], chain: _Chain) -> None:
    """One hop into a same-file helper called on the chain."""
    for m in _CALLED.finditer(text):
        h = index.get(m.group("name"))
        if h is not None and h not in chain.helpers and _reads_in_helper(f, h):
            chain.helpers.append(h)
            chain.evidence.append(at)


def _controlled_by(f: _File, lo: int, send: int, chain: _Chain, wrappers: list[str],
                   pred: Callable[[str], bool]) -> bool:
    if _wrapped(wrappers, pred) or gated(f.codes, lo, send, pred):
        return True
    return any(gated(f.codes, hh + 1, _helper_end(f.codes, hh), pred) for hh in chain.helpers)


def _controlled(f: _File, h: int, send: int, chain: _Chain, wrappers: list[str]) -> bool:
    key = ("controlled", h, send, tuple(chain.helpers))
    if key not in f.memo:
        lo = max(h + 1, send - _MAX_UP, 0)
        f.memo[key] = any(_controlled_by(f, lo, send, chain, wrappers, p)
                          for p in (is_principal, is_human_check))
    return f.memo[key]


# ── finding ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Where:
    """Line numbers (1-based) the description cites: nothing else from the
    scanned source reaches the judge or a report through it."""
    read: int
    send: int
    span: tuple[int, int] | None    # the handler the rule checked for a gate
    wrapper: int | None             # first line outside it that names it


def _checked(w: _Where) -> str:
    if w.span is None:
        return "Checked the file"
    text = f"Checked handler L{w.span[0]}-L{w.span[1]}"
    return text + (f" and wrapper L{w.wrapper}" if w.wrapper else "")


def _description(w: _Where) -> str:
    """Within the judge's 300 characters; the wrapper is dropped first."""
    for where in (w, _Where(w.read, w.send, w.span, None)):
        text = (
            f"Caller sets the recipient (L{where.read}) of a message sent at L{where.send}. "
            f"{_checked(where)}: no auth or human check gates the send; a per-sender/recipient "
            "quota does not bound it. Refuted by: auth on every route here, a server-verified "
            "CAPTCHA before the send, or a non-caller recipient."
        )
        if len(text) <= 300:
            return text
    return text[:300]


def _finding(file_path: Path, f: _File, where: _Where, quota: bool) -> dict:
    read, send = where.read, where.send
    finding = {
        "severity": "medium" if quota else "high",
        "check_id": CHECK_ID,
        "category": "CWE-799",
        "title": _TITLE,
        "description": _description(where),
        "file_path": str(file_path),
        "line_start": read,
        "line_end": send,
        "recommendation": _RECOMMENDATION,
    }
    first = max(read, send - _SNIPPET_SPAN)
    finding["code_snippet"] = extract_snippet(f.lines, first, context=2, max_chars=None,
                                              line_end=send)
    return enrich_finding(finding, "799")


def _declares(code: str, name: str) -> bool:
    """The match is the name a function header declares, not a call."""
    return _is_header(code) and _header_name(code) == name


def _recipient_of(f: _File, idx: int, m: re.Match) -> str | None:
    if _declares(f.codes[idx], m.group("name")):
        return None
    return recipient(_call_args(f.codes, idx, m.end() - 1))


def _where(f: _File, h: int, read: int, send: int) -> _Where:
    if h < 0:
        return _Where(read, send, None, None)
    end = body_end(f.codes, h)
    name = _header_name(f.codes[h])
    outside = (i for i, c in enumerate(f.codes)
               if (i < h or i >= end) and name and name in c and name in _idents(c))
    first = next(outside, None)
    return _Where(read, send, (h + 1, end), None if first is None else first + 1)


def _handler_wrappers(f: _File, h: int) -> list[str]:
    key = ("wrappers", h)
    if key not in f.memo:
        name = _header_name(f.codes[h]) if h >= 0 else None
        f.memo[key] = _wrapper_lines(f, h, body_end(f.codes, h), name)
    return f.memo[key]


def _addressed(m: re.Match, chain: _Chain) -> bool:
    """The recipient is an address: the call names an address channel, or a
    contact-shaped name is on the recipient's chain."""
    words = segments(m.group("name")) + segments(m.group("recv") or "")
    if any(w.endswith(_ADDRESS_CHANNEL) or w.startswith(_ADDRESS_CHANNEL) for w in words):
        return True
    return any(_contact_shaped(n) for n in chain.names)


def _check_send(file_path: Path, f: _File, idx: int, m: re.Match, index: dict[str, int]) -> dict | None:
    who = _recipient_of(f, idx, m)
    if who is None:
        return None
    h = function_header(f.codes, idx)
    lo = max(h + 1, idx - _MAX_UP, 0)
    chain = _walk(f, who, lo, idx, index)
    if not chain.evidence or not _addressed(m, chain):
        return None
    wrappers = _handler_wrappers(f, h)
    if _controlled(f, h, idx, chain, wrappers):
        return None
    quota = any(_control_idents(c, _is_quota) for c in (*f.codes[lo:idx], *wrappers))
    return _finding(file_path, f, _where(f, h, max(chain.evidence) + 1, idx + 1), quota)


def _sends(file_path: Path, f: _File) -> Iterator[tuple[int, re.Match]]:
    """Every send call in the file, at most ``_MAX_SENDS`` (logged when cut)."""
    found = ((idx, m) for idx, code in enumerate(f.codes) for m in SEND_CALL.finditer(code)
             if is_send_call(m.group("recv"), m.group("name")))
    yield from islice(found, _MAX_SENDS)
    if next(found, None) is not None:
        logger.warning("message_send_truncated file=%s cap=%d", file_path, _MAX_SENDS)


def _one_per_origin(rows: Iterator[dict | None]) -> Iterator[dict]:
    """One row per recipient origin: a handler that sends the same caller-chosen
    address several messages is one weakness, judged once."""
    seen: set[tuple[str, int]] = set()
    for row in rows:
        key = (row["file_path"], row["line_start"]) if row else None
        if key is not None and key not in seen:
            seen.add(key)
            yield row


def check_message_sends(file_path: Path, lines: list[str], findings: list[dict]) -> None:
    """Emit one CWE-799 row per anonymous, caller-addressed send in the file."""
    if not SEND_CALL.search("\n".join(lines)):
        return
    bounded = [line if len(line) <= _MAX_LINE_CHARS else "" for line in lines]
    f = _File(lines=lines, codes=code_lines(bounded))
    index = _function_index(f.codes)
    findings.extend(_one_per_origin(_check_send(file_path, f, idx, m, index)
                                    for idx, m in _sends(file_path, f)))
