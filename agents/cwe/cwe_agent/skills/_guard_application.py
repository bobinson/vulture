"""Predicates for the guard-application rule of ``access_control_check``.

Feature 0097. The weakness: an authentication or authorization guard EXISTS,
but whether it runs, is skipped, or is satisfied is decided by a request
attribute the client controls (a header, query parameter, body field or
cookie). That is CWE-807, Reliance on Untrusted Inputs in a Security Decision;
when the attribute is a client-asserted source identity (X-Forwarded-For, Host,
Referer, User-Agent, ...) it is CWE-290, Authentication Bypass by Spoofing.

Three arms, each of which needs three co-occurring signals because every row is
``high`` and blocks the offline pre-commit gate:

* imperative: a branch reads a client attribute (directly, or through a
  one-hop alias), its OWN body skips the guard or grants access, and guard
  evidence follows in the ENCLOSING scope (unless the outcome is intrinsically
  a guard decision, such as ``context.Succeed``). Guard evidence is a DENY; a
  mere read of the caller's identity counts only as a negated condition whose
  own body turns the request away;
* route matcher: a ``has`` / ``missing`` condition inside the bracket span of a
  ``matcher:`` value is typed ``header`` / ``cookie`` / ``query``, and the
  module outside that span carries guard evidence;
* declarative exclusion: a framework's own exclusion hook for a named auth
  guard (Rails ``skip_before_action ... if:`` / ``before_action ... unless:``,
  Spring ``RequestHeaderRequestMatcher`` + ``permitAll()``,
  ``.unless({ custom })``, Echo/Fiber ``Skipper``) keyed on a client attribute.

Equality with a value the client cannot know (an env or config value, a field,
an imported constant) is a shared secret, i.e. authentication, and is vetoed in
both the imperative and the declarative arm. Only a literal that IS the whole
comparand, or an identifier bound in the same file only to such literals
(``FileView.literal_names``), is a value the client can know.

Nothing here reads a filename, a suffix or a framework import: the corpus and
the offline runner both stage files under neutral names.

A private helper module (``_args.py`` precedent): no SKILL_MAP entry and no
category literal. The spec dicts that carry the CWE literals live in
``access_control_check.py``; that module passes its own ``_has_authz`` and
``ROLE_STRING_CMP`` in through :class:`FileView`, which avoids an import cycle.

Structure (branch keywords, accessor roots, matcher keys, brackets) is matched
on the code view, where strings and comments are blanked; names and literals
are read from the raw line. A missed strip can only add a candidate, which must
still pass the other signals.

ReDoS: every free gap is bounded and no quantifier is nested over an
overlapping class; ``bracket_span`` and the scope walks are linear and capped.
Guard evidence is computed once per file (``FileView.evidence_prefix``), so
the matcher arm is linear in file size however many matchers a file holds.
"""

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from functools import cached_property
from itertools import accumulate, chain

from cwe_agent.skills.web_security_check import PRIV_COOKIE_NAME
from shared.tools.file_scanner import COMMENT_INDICATORS
from shared.tools.line_context import strip_strings_and_comments
from shared.tools.snippet import collect_scoped_body

# --- vocabulary ------------------------------------------------------------------
# Single-sourced: resource_check.SPOOFABLE_CLIENT_HEADER is composed from this.
CLIENT_IP_HEADER = (
    r"(?:x-)?(?:forwarded-for|forwarded|real-ip|client-ip|true-client-ip|cf-connecting-ip)"
)

_NAME = r"""['"`]?(?P<name>[A-Za-z_][\w-]*)"""
# `?.` is optional chaining: `req.headers?.["x"]` and `req.headers?.get("x")`.
_CONN = (
    r"(?:\??\.?\s*\[\s*:?|\??\.\s*(?:get|has|ContainsKey|TryGetValue)\s*\(\s*|\??\.\s*|\(\s*)"
)
# (kind, accessor). Receiver-anchored and case-SENSITIVE, which keeps Go
# `r.Header` apart from JS `req.headers`. Server-observed values (req.ip,
# remote_addr, RemoteAddr, path, method, req.user, session) are NOT accessors.
_ACCESSORS = (
    # Koa: `ctx.request.headers`.
    ("header", rf"(?<![\w$.])(?:ctx\s*\.\s*)?(?:req|request|ctx|context)\s*\.\s*headers?\s*{_CONN}"),
    ("header", r"(?<![\w$.])(?:req|request|ctx)\s*\.\s*(?:get|header)\s*\(\s*"),
    ("header", r"(?<![\w$.])\w*(?:[Rr]eq|[Rr]equest)\s*\.\s*getHeader\s*\(\s*"),
    ("header", r"(?<![\w$.])(?:r|req|request)\s*\.\s*Header\s*(?:\.\s*Get\s*\(\s*|\[\s*)"),
    ("header", r"(?<![\w$.])c\s*\.\s*(?:GetHeader|Request\s*\(\s*\)\s*\.\s*Header\s*\.\s*Get)\s*\(\s*"),
    # Fiber's `c.Get(name)` is the header; gin's `c.Get(key)` reads the server-side
    # context store and returns two values, so it is never compared directly.
    ("header", r"""(?<![\w$.])c\s*\.\s*Get\s*\(\s*(?=["'`][^"'`\n]{0,80}["'`]\s*\)\s*[!=]=)"""),
    ("header", r"(?<![\w$.])c\s*\.\s*req\s*\.\s*header\s*\(\s*"),  # Hono
    ("header", r"(?<![\w$.])request\s*\.\s*get_header\s*\(\s*"),  # Rack; name must start HTTP_
    ("header", r"\$_SERVER\s*\[\s*"),  # name must start HTTP_
    ("header", r"(?<![\w$.])request\s*\.\s*META\s*(?:\[\s*|\.\s*get\s*\(\s*)"),  # name must start HTTP_
    ("header", r"\$request\s*->\s*(?:header|hasHeader|headers\s*->\s*get)\s*\(\s*"),
    ("header", rf"(?<![\w$])Request\s*\.\s*Headers\s*{_CONN}"),
    ("query", r"(?<![\w$.])(?:req|ctx|request)\s*\.\s*query\s*(?:\??\.?\s*\[\s*|\??\.\s*)"),
    ("query", r"(?<![\w$.])request\s*\.\s*(?:args|GET|query_params|values)\s*(?:\[\s*|\.\s*get\s*\(\s*)"),
    ("query", r"\bsearchParams\s*\.\s*(?:get|has)\s*\(\s*"),
    ("query", r"\bURL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(\s*"),
    ("query", r"(?<![\w$.])c\s*\.\s*(?:Query|QueryParam|DefaultQuery|req\s*\.\s*query)\s*\(\s*"),
    ("query", r"(?<![\w$.])\w*(?:[Rr]eq|[Rr]equest)\s*\.\s*getParameter\s*\(\s*"),
    ("query", r"\$_(?:GET|REQUEST)\s*\[\s*"),
    ("query", r"\$request\s*->\s*(?:query|input|boolean)\s*\(\s*"),
    ("query", r"(?<![\w$.])r\s*\.\s*FormValue\s*\(\s*"),
    ("query", r"(?<![\w$.@])params\s*\[\s*:?"),
    ("query", rf"(?<![\w$])Request\s*\.\s*(?:Query|Form)\s*{_CONN}"),
    ("body", r"(?<![\w$.])(?:req|ctx\s*\.\s*request)\s*\.\s*body\s*(?:\??\.?\s*\[\s*|\??\.\s*)"),
    ("body", r"(?<![\w$.])request\s*\.\s*(?:form|json|POST|data)\s*(?:\[\s*|\.\s*get\s*\(\s*)"),
    ("body", r"\$_POST\s*\[\s*"),
    ("cookie", r"(?<![\w$.])(?:req|request)\s*\.\s*(?:cookies|COOKIES)\s*"
               r"(?:\??\.?\s*\[\s*|\??\.\s*get\s*\(\s*|\??\.\s*)"),
    ("cookie", r"\bcookies\s*\(\s*\)\s*\.\s*get\s*\(\s*"),
    ("cookie", r"(?<![\w$.])r\s*\.\s*Cookie\s*\(\s*"),
    ("cookie", r"(?<![\w$.@])cookies\s*\[\s*:?"),  # Rails
    ("cookie", r"\$_COOKIE\s*\[\s*"),
    ("cookie", r"\$request\s*->\s*cookie\s*\(\s*"),
    ("cookie", rf"(?<![\w$])Request\s*\.\s*Cookies\s*{_CONN}"),
    ("cookie", r"(?<![\w$.])ctx\s*\.\s*cookies\s*\.\s*get\s*\(\s*"),  # Koa
    # A client-asserted identity read as a property or method (Go
    # `r.UserAgent()` / `r.Host`, Express `req.hostname`, Flask
    # `request.user_agent`): the name IS the member.
    ("header", r"(?<![\w$.])(?:r|req|request)\s*\.\s*"
               r"(?=(?:UserAgent|Referer|Host|host|hostname|user_agent|referrer|referer)\b)"),
)
# Python membership names the attribute BEFORE its container:
# `if "X-Internal" in request.headers:`. `"X" not in request.headers` is not a
# read (the lookahead has no `not`), so the negation needs no special case.
_NAME_FIRST = (
    ("header", "headers"), ("query", "args|GET|query_params|values"),
    ("body", "form|POST|json"), ("cookie", "cookies|COOKIES"),
)
_NAME_FIRST_ACC = tuple(
    (kind, rf"\bin\s+request\s*\.\s*(?:{c})\b",
     rf"""['"](?P<name>[A-Za-z_][\w-]*)(?=['"]\s+in\s+request\s*\.\s*(?:{c})\b)""")
    for kind, c in _NAME_FIRST
)
# Each accessor twice: the root alone (stripped code) and root + name (raw line).
_ACC = (
    *((k, re.compile(a), re.compile(a + _NAME)) for k, a in _ACCESSORS),
    *((k, re.compile(root), re.compile(full)) for k, root, full in _NAME_FIRST_ACC),
)
# A comparand that is itself a request read (`=== req.cookies.x`,
# `== request.args.get("role")`): the client sets both sides, so it is not a
# shared secret. Each new pattern below starts only at the edge of a blank run
# (a lookbehind), so a search over a long run stays linear.
CLIENT_READ = re.compile(r"(?<![\s(!])[\s(!]*+(?:" + "|".join(a for _, a in _ACCESSORS) + ")")
# `matcher: [...]`, or `const matcher = [...]` bound by `config = { matcher }`.
MATCHER_KEY = re.compile(r"\bmatcher\s*:|\b(?:const|let|var)\s+matcher\s*(?::[^=\n]{0,60})?=(?!=)")
# Rails filter declarations: `skip_before_action ... if:` and the guard's own
# `before_action ..., unless:` / `if:` (also `around_` / `prepend_`, `_filter`).
RAILS_FILTER = re.compile(r"\b(?:skip_|prepend_)?(?:before|around)_(?:action|filter)\b")
# One search per file before any per-line work.
GUARD_BYPASS_HINT = re.compile(
    "|".join(a for _, a in _ACCESSORS)
    + "|" + "|".join(root for _, root, _full in _NAME_FIRST_ACC)
    + r"|\bmatcher['\"]?\s*:|" + MATCHER_KEY.pattern
    + r"|\bSkipper\s*:|RequestHeaderRequestMatcher|" + RAILS_FILTER.pattern + r"|\bcustom\s*:"
)

CREDENTIAL_ATTR = re.compile(
    r"^(?:authorization|proxy-authorization|cookie|(?:x-)?api[-_]?key"
    r"|(?:x-)?(?:auth|api|access|bearer)[-_]?token|(?:access_|id_|refresh_)?token|jwt"
    r"|session(?:id|_id)?|sid|jsessionid|(?:x-)?(?:hub-)?signature(?:-256)?"
    r"|(?:x-)?_?(?:csrf|xsrf)(?:[-_]?token)?|csrfmiddlewaretoken|authenticity_token)$",
    re.IGNORECASE,
)
# Pagination / output-format / locale / tracing / CORS-preflight names are never
# guard decisions. `origin` stays here: comparing it is the recommended CSRF
# defence, so a compared Origin is not reported as a spoofed identity.
NEUTRAL_ATTR = re.compile(
    r"^(?:accept(?:-[\w-]+)?|content-[\w-]+|x-request-id|x-correlation-id|traceparent"
    r"|tracestate|if-none-match|if-modified-since|cache-control|x-requested-with|origin"
    r"|access-control-request-(?:method|headers)"
    r"|lang|locale|theme|format|fmt|page|per_page|page_size|limit|offset|cursor|sort"
    r"|order|q|search|callback)$",
    re.IGNORECASE,
)
# Identity headers injected by an authenticating gateway (IAP, Easy Auth, ALB OIDC,
# Cloudflare Access, oauth2-proxy). Trusting them is the deployment's design.
GATEWAY_IDENTITY = re.compile(
    r"^(?:x-forwarded-(?:user|email|preferred-username|groups)|x-goog-authenticated-user-[\w-]+"
    r"|x-goog-iap-jwt-assertion|x-ms-client-principal[\w-]*|x-amzn-oidc-[\w-]+"
    r"|x-forwarded-client-cert|cf-access-[\w-]+|(?:x-)?remote-user)$",
    re.IGNORECASE,
)
IDENTITY_ATTR = re.compile(
    rf"^(?:{CLIENT_IP_HEADER}|(?:x-)?(?:cluster-client-ip|originating-ip|forwarded-host)"
    r"|host(?:name)?|referr?er|user[-_]?agent)$",
    re.IGNORECASE,
)
PRIV_COOKIE = re.compile(rf"^(?:{PRIV_COOKIE_NAME})$", re.IGNORECASE)  # web_security CWE-784/565 owns these

BRANCH = re.compile(r"(?:^|[^\w.$])(?:if|elif|else\s+if|elsif|unless)\b(?!\s*:)")
# Searched over the condition AND the branch's own body: a webhook branch that
# verifies its signature (`constructEvent`, `isValidShopifyRequest`) is
# authenticated, wherever the verifier call sits.
VERIFIER = re.compile(
    r"hmac|compare_digest|secure_compare|timingSafeEqual|constructEvent|\bverify\w*\s*\(|jwtVerify"
    r"|validate\w*Signature|checkSignature|itsdangerous|MessageDigest\s*\.\s*isEqual"
    r"|ConstantTimeCompare|\bisValid\w{0,40}?(?:Request|Signature|Webhook|Hmac)\s*\("
    r"|\w{0,40}signature\w{0,40}\s*\(",
    re.IGNORECASE,
)
# A call CONJOINED with the read whose name says it verifies a credential
# (verb + credential noun: `check_service_jwt(`, `verifyToken(`). Searched on the
# condition only. Never a disjunction, and never a negated call: `!` / `not`
# cannot precede the call in the first alternative, and in the second one a
# negation (also before `await`, with any whitespace) is captured as `neg` and
# the match rejected by `verified_conjunct`. A CSRF validator
# (`validateCsrfToken(`) proves the request came from the app's own page, not
# who sent it, so it is not a verifier.
_VERIFY_CALL = (
    r"(?:[\w$]{1,40}\s*\.\s*){0,2}(?![\w$]{0,40}?(?i:csrf|xsrf))"
    r"(?i:verify|authenticate|check|validate|is_?valid)_?\w{0,30}?"
    r"(?i:jwt|token|signature|sig|hmac|auth|credentials?|session)\s*\("
)
VERIFIED_CONJUNCT = re.compile(
    rf"(?:&&|\band\b)\s*(?:await\s+)?{_VERIFY_CALL}"
    rf"|(?<![\w$.!])(?P<neg>!\s*|\bnot\s+)?(?:await\s+)?{_VERIFY_CALL}[^()\n]{{0,120}}\)\s*(?:&&|\band\b)"
)
# Veto 5, the comparand model. A literal is a value the client can know; a
# template with `${` is not a literal.
_LIT = (
    r"""(?:["'](?:[^"'\\\n]|\\.){0,200}["']|`[^`$\n]{0,200}`|-?\d[\w.]*"""
    r"|true|false|True|False|null|nil|None|undefined)"
)
# One terminator vocabulary for both halves of veto 5 (`{` closes a condition
# with no parentheses, and is harmless after a literal).
_COMPARAND_END = r"(?:[)\]{:?,]|&&|\|\||\band\b|\bor\b|\bthen\b|$)"
# The literal must be the WHOLE comparand: `'cron:' + SECRET` is not knowable.
# A block comment may follow it: `=== 'yes' /* local only */)`.
_BLOCK_COMMENT = r"(?:/\*[^*\n]{0,200}+\*/\s*+)?"
LITERAL_COMPARAND = re.compile(rf"^[\s(!]*{_LIT}\s*+{_BLOCK_COMMENT}{_COMPARAND_END}")
# An identifier, bare or qualified by a TYPE (`Mode.Bypass`, `Flags.BYPASS`,
# `Constants.Mode.X`, PHP `self::BYPASS` / `static::`); the LAST segment is
# resolved against the file's literal bindings. A lower-case qualifier is an
# instance or a module (`settings.x`, `cfg.x`, `config.x`, `process.env.X`,
# `this.x`, `self.x`): runtime-loaded state, never resolved, even when a
# same-named literal (a field DEFAULT) exists in the file.
COMPARAND_IDENT = re.compile(
    r"^[\s(!]*(?:(?:(?P<q1>[A-Z]\w{0,40})\s*(?:\.|::)|(?:self|static)\s*::)\s*"
    r"(?:(?P<q2>[A-Za-z_]\w{0,40})\s*(?:\.|::)\s*)?)?"
    rf"(?P<id>\$?[A-Za-z_]\w{{0,60}})\s*{_COMPARAND_END}"
)
# An enum member read through `.value` / `.name` (`Mode.BYPASS.value`) is the
# member's literal: the suffix is dropped before resolving.
_ENUM_VALUE = re.compile(r"(?<!\s)\s*+\.\s*+(?:value|name)\b")
# A same-file binding `<lhs> = <rhs>` (any modifiers / type on the left). Not
# `_ASSIGN`: that one is shared with alias detection and must stay narrow.
_DECL = re.compile(r"^(?P<lhs>[^=\n'\"`]{1,160}?)(?<![=!<>])=(?!=)\s*(?P<rhs>.*)$")
# The RHS is a literal, optionally narrowed (TS `as const`, `as string`,
# `satisfies T`) and closed by `;,)}`, `.freeze` and a comment. Possessive `\s*+`: the
# optional-whitespace runs otherwise backtrack cubically on a literal followed
# by a long blank run (measured: a 4000-space tail never finished in 8 s). This
# runs on every line of a file.
_LIT_RHS = re.compile(
    rf"^{_LIT}\s*+(?:(?:as|satisfies)\s++[\w.<>\[\]|]{{1,60}}+\s*+)?{_BLOCK_COMMENT}"
    r"[;,)}]?\s*+(?:\.freeze)?\s*+(?:(?://|#|/\*).*)?$"
)
# `const A = 'x', B = 'y'`: the next declarator after a literal (only after
# `const` / `let` / `var`, where a top-level comma separates declarators).
_DECL_KEYWORD = re.compile(r"\b(?:const|let|var)\b")
_NEXT_DECLARATOR = re.compile(rf"^(?P<lit>{_LIT})\s*+,\s*+(?P<rest>[$A-Za-z_][\w$]{{0,60}}\s*+=(?!=).*)$")
_MAX_DECLARATORS = 16
# A same-line object literal (`{ debug: 'on' }`, `Object.freeze({ BYPASS: 'yes' })`):
# each `key: <literal>` member binds `OBJ.key` (qualified by the object, never
# the bare key), so `FLAGS.BYPASS` resolves.
_OBJECT_RHS = re.compile(r"^(?:Object\s*\.\s*freeze\s*\(\s*)?\{(?P<body>[^{}\n]{0,400}+)\}")
_LIT_MEMBER = re.compile(rf"""(?:^|,)\s*+['"]?(?P<key>[$A-Za-z_][\w$]{{0,60}})['"]?\s*+:\s*+{_LIT}\s*+(?=,|$)""")
# An imported name (`from x import NAME`, `import NAME`) is bound to something
# other than a same-file literal, even when a fallback literal follows.
_IMPORT = re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+(?P<names>[^;\n]{1,400})")
# PHP `define('NAME', <literal>)` binds NAME; any other value binds it to `other`.
_DEFINE = re.compile(
    rf"""^\s*define\s*\(\s*['"](?P<name>[A-Za-z_]\w{{0,60}})['"]\s*+,\s*+(?P<lit>{_LIT}\s*+\))?"""
)
# An assignment ANYWHERE on a line (`if (prod) secret = env.X;`, a callback
# `.then((s) => { secret = s.k })`, a second statement, Go `{ secret = v }`, a
# compound `+=`, `:=`): a value that does not START with a literal binds the name
# to `other`, so a literal that is only a DEFAULT is not a value the client can
# know. Never a comparison (`==`, `!=`, `<=`) or an arrow (`=>`).
_ANY_ASSIGN = re.compile(
    r"(?<![\w$.>])(?P<name>[$A-Za-z_][\w$]{0,60}+)\s*+(?:[-+*/%|&^:]|\?\?|\|\||&&|<<|>>)?=(?![=>~])"
)
_LIT_START = re.compile(rf"(?<!\s)\s*+{_LIT}\s*+(?:[;,)}}\]]|as\b|satisfies\b|/[/*]|#|$)")
# Open brackets are tracked across lines: a binding whose INNERMOST open bracket
# is `(` is a parameter default or a keyword argument, not a declaration; one
# inside a callback BODY (`app.use((req, res) => {`) is a declaration. A line
# starting in column 0 is top-level and clears the stack, so one unbalanced
# bracket (a regex literal) cannot leak through the rest of a file.
_BRACKET = re.compile(r"[(){}\[\]]")
_TOP_LEVEL = re.compile(r"^[A-Za-z_$@]")
# Go `const (` / `var (` opens a declaration group, not a call.
_DECL_GROUP = re.compile(r"^\s*(?:const|var)\s*\(\s*$")
# A placeholder that is loaded later (`let t = ''`, `KEY = None`) is not a value.
_PLACEHOLDER = re.compile(r"^(?:null|nil|None|undefined|''|\"\")")
_DECL_NAME = re.compile(r"\$?[A-Za-z_]\w{0,60}")
COMPARISON = re.compile(
    r"===?|!==?|\bin\b|\.has\s*\(|\.includes\s*\(|startsWith\s*\(|endsWith\s*\(|\.contains\s*\("
    r"|\bContains\s*\(|in_array\s*\(|\.test\s*\(|\.match\s*\(|\.equals\w*\s*\(|\.indexOf\s*\("
    r"|\.(?:startswith|endswith)\s*\(|\bHas(?:Prefix|Suffix)\s*\(|\bEqualFold\s*\("
)
# A map / set lookup keyed by the read: `trusted[r.Header.Get("X-Real-IP")]`.
INDEXED_BY = re.compile(r"\w\s*\[\s*$")
# The value the read is compared AGAINST (veto 5 reads only this, never the
# whole condition, so a feature-flag conjunct cannot hide the bypass). A default
# argument is skipped: `request.headers.get("X-Key", "") == KEY`.
_COMPARAND_AFTER = re.compile(
    r"""^['"`]?(?:\s*+,[^()\n]{0,80}+)?\s*+\]?\s*+\)?\s*+"""
    r"""(?:===?|!==?|\.\s*equals\w*\s*\()\s*(?P<c>[^&|;{}]{0,200})"""
)
_COMPARAND_BEFORE = re.compile(
    r"(?P<c>[\w$.\[\]()'\"]{1,200})\s*(?:===?|!==?|\.\s*equals\w*\s*\()\s*$"
)
# A static two-argument equals (`Objects.equals(<read>, X)`,
# `StringUtils.equals(...)`): the comparand is the OTHER argument, never the
# receiver type.
_EQUALS_CALL_BEFORE = re.compile(r"\.\s*equals\w*\s*\(\s*$")
_SECOND_ARG = re.compile(r"""^['"`]?\s*+\)\s*+,\s*+(?P<c>[^&|;{}]{0,200})""")
NEG_BEFORE = re.compile(r"(?:!|\bnot\s+|\bempty\s*\(\s*|!\s*isset\s*\(\s*)$")
# Possessive `\s*+`: three adjacent optional-whitespace runs otherwise backtrack
# cubically on a long blank tail (measured: a 4000-space operand never finished).
NEG_AFTER = re.compile(r"""^['"`]?\s*+\]?\s*+\)?\s*+(?:===?|\bis)\s*(?:null|undefined|None|nil|""|'')""")
# `view` / `view_function` / any `<ident>(*args` pass-through count as the skip.
SKIP_RETURNING = re.compile(
    r"\breturn\s+(?:await\s+)?(?:_?next|call_next|\$next|NextResponse\s*\.\s*next"
    r"|(?:c|ctx)\s*\.\s*Next"
    r"|(?:self\s*\.\s*)?get_response|f|fn|func|view|view_func|view_function|wrapped|handler)\s*\("
    r"|\breturn\s+\w{1,40}\s*\(\s*\*\s*args\b"
)
SKIP_CALL = re.compile(
    r"\bnext\s*\.\s*ServeHTTP\s*\(|\b(?:chain|filterChain|fc)\s*\.\s*doFilter\s*\("
    r"|(?<![\w.])c\s*\.\s*Next\s*\(\s*\)|(?<![\w.])next\s*\(\s*\)"
    r"|(?<![\w.])_next\s*(?:\.\s*Invoke\s*)?\(\s*(?:\w{1,20}\s*)?\)"  # ASP.NET middleware
    r"|(?<![\w.])next\s*(?:\.\s*Invoke\s*)?\(\s*(?:context|ctx|httpContext)\s*\)"  # app.Use lambda
)
# The branch body ends in `} else` / `} else if`: a lone `next()` is the skip.
ELSE_TAIL = re.compile(r"^\s*\}\s*else\b")
RETURN_STMT = re.compile(r"(?:^\s*|[{;]\s*)return\s*;?\s*$")
# Python `return None` / Ruby `return nil` continue a before-request hook too.
BARE_RETURN = re.compile(r"(?:^\s*|[{:;]\s*)return(?:\s++(?:None|nil)\b)?\s*+;?\s*+$")
PRE_HOOK = re.compile(
    r"@\w+\s*\.\s*before(?:_app)?_request\b"
    r"|addHook\s*\(\s*['\"](?:onRequest|preHandler|preValidation)"
)
# The flag may hang off the request-scoped object (`req.authenticated = true`,
# `g.authenticated = True`, `request.state.authed = True`, `res.locals.authed = true`,
# `$this->allowed = true`).
GRANT_FLAG = re.compile(
    r"(?<![\w.])(?:(?:request\s*\.\s*state|ctx\s*\.\s*state|res\s*\.\s*locals|req|request|g|self|this|ctx)"
    r"\s*\.\s*|\$this\s*->\s*)?"
    r"\$?(?:is_?)?(?:authori[sz]ed|authenticated|authed|allowed|logged_?in|admin)"
    r"\s*=\s*(?:true|1)\b",
    re.IGNORECASE,
)
GRANT_SUCCEED = re.compile(r"\b(?:context|ctx)\s*\.\s*Succeed\s*\(")
GRANT_RETURN_TRUE = re.compile(r"\breturn\s+(?:true|True)\b")
GUARD_FN = re.compile(
    r"\b(?:canActivate|has_permission|has_object_permission|authori[sz]e\w*|is_?authori[sz]ed"
    r"|isAllowed|is_allowed|check_?(?:auth|access|permission)\w*|can_access|hasAccess)\s*\("
)
# `return true` in a Spring `preHandle` CONTINUES the chain: it is a skip (guard
# evidence must follow), not an intrinsic grant, so it is not in GUARD_FN.
INTERCEPTOR_FN = re.compile(r"\bpreHandle\s*\(")
# The branch hands back a principal built from the request (a FastAPI
# dependency's `return User(...)`). Case-sensitive: a constructor, not a lookup.
# The principal noun ENDS the name (`User(`, `AuthUser(`, `ClaimsPrincipal(`,
# or a persisted `UserEntity(`);
# `UserPreview(` / `UserSummary(` / `UserDto(` are data, not an identity. An
# anonymous or guest principal asserts no identity, so it grants nothing.
PRINCIPAL_RETURN = re.compile(
    r"\breturn\s+(?:await\s+)?(?:new\s+)?(?:\w{1,40}\s*\.\s*)?(?!Anonymous|Guest)(?:[A-Z]\w{0,30}?)?"
    r"(?:User|Principal|Identity|Claims)(?:Entity|Model|Record)?\s*\("
)
# ...and only from a principal PROVIDER: a function whose name ends in the noun
# it provides (`get_current_user`, `getUser`, `authenticate`, `resolvePrincipal`),
# or a Passport strategy's `validate(`; never a route handler that happens to
# return a user object.
PRINCIPAL_PROVIDER = re.compile(
    r"(?:\b(?:def|function|func|async)\s+(?:\([^)\n]{0,80}\)\s*)?"
    r"|^\s*(?:(?:public|private|protected|internal|static|override|async)\s+)+(?:[\w$<>\[\].?]{1,60}\s+)?)"
    r"[\w$]{0,60}?(?i:user|principal|identity|claims|authenticate|auth)\s*\("
    r"|^\s*(?:(?:public|async)\s+)*validate\s*\("
)


def _status_deny(codes: str, words: str, upper: str) -> str:
    """The status idioms of a deny with the given codes (``401|403``), status
    words (``Unauthorized|Forbidden``) and constant spellings (``UNAUTHORIZED``)."""
    return (
        r"(?:\bstatus(?:_?[Cc]ode)?\s*[(:=]\s*|\bsendStatus\s*\(\s*|\babort\s*\(\s*"
        r"|\bhttp_response_code\s*\(\s*|\bAbortWithStatus\w*\s*\(\s*|\bStatus(?:Code)?\s*[(:=]\s*"
        r"|\b(?:writeHead|WriteHeader|code|SendStatus|throw|createError|HTTPException|sendError)"
        rf"\s*\(\s*(?:status_code\s*=\s*)?)(?:{codes})\b"
        rf"|,\s*(?:{codes})\s*\)?\s*;?\s*$|\bStatusCodes\s*\.\s*Status(?:{codes})\w*"
        rf"|\bStatus(?:{words})\b|\bHTTP_(?:{codes})_\w+|\bErr(?:{words})\b"
        rf"|\bHttpStatus(?:Code)?\.(?:{upper}|{words})\b"
        rf"|\bSC_(?:{upper})\b|\bHttpResponse(?:{words})\b"
    )


# A guard call that authenticates, as opposed to a bare status deny.
NAMED_GUARD = re.compile(
    r"\bjwt\s*\.\s*verify\s*\(|\bjwtVerify\s*\(|\bverifySession\s*\(|\bauthenticate\w+\s*\("
    r"|\bpassport\s*\.\s*authenticate\s*\(|\blogin_required\b|\bwithAuth\s*\("
    r"|\b[Rr]equire_?(?:[Uu]ser|[Ll]ogin|[Aa]uth)\w{0,20}\s*\("
    r"|\b[Ee]nsure_?(?:[Aa]uth|[Ll]ogged)\w{0,20}\s*\("
)
# A DENY: a 401/403 in any of the common idioms, an auth exception, a verifier
# that throws, a named guard or guard wrapper. On its own it is guard evidence.
GUARD_EVIDENCE = re.compile(
    _status_deny("401|403", "Unauthorized|Forbidden", "UNAUTHORIZED|FORBIDDEN")
    + r"|\b(?:PermissionDenied|Unauthorized\w*|Forbidden\w*|AccessDenied\w*|NotAuthenticated)\s*\("
    + "|" + NAMED_GUARD.pattern,
    re.MULTILINE,
)
# A deny that says AUTHENTICATION (401), not merely "not allowed" (403).
AUTHN_DENY = re.compile(
    _status_deny("401", "Unauthorized", "UNAUTHORIZED")
    + r"|\b(?:Unauthorized\w*|NotAuthenticated)\s*\(",
    re.MULTILINE,
)
# An attribute NAMED as a feature or challenge gate (beta, opt-in, consent,
# captcha clearance, experiment, ...) or as a routing selection (tenant, API
# version). Gating on it is not an auth decision, so its own fall-through 403
# is not guard evidence; an INDEPENDENT guard must follow. The gate word is a
# whole segment of the name (`cookie_consent`), and a name carrying a BYPASS
# word anywhere (`x-admin-clearance`, `skip_auth_variant`, `beta_admin_bypass`)
# is a bypass name, not a gate.
FEATURE_GATE = re.compile(
    r"^(?!.*(?:skip|bypass|auth|admin|internal|debug|override|trust|privileg|super|root|sudo"
    r"|backdoor|impersonat|staff))"
    r"(?:[\w-]{0,30}?[-_])?(?:beta|opt[-_]?in|consent|captcha|cf_clearance|clearance|challenge"
    r"|experiment|variant|ab[-_]?test|age[-_]?(?:gate|verified)|waitlist|early[-_]?access"
    r"|tenant|(?:api|client|app)?[-_]?version)(?:[-_][\w-]{0,30})?$",
    re.IGNORECASE,
)
# Comparing the Referer is a CSRF defence (OWASP lists Origin OR Referer): a
# browser cannot forge it cross-site. Like a feature gate, its own 403 is not
# guard evidence; a Referer that skips a 401 guard is still a spoofed identity.
CSRF_IDENTITY = re.compile(r"^referr?er$", re.IGNORECASE)
_NON_AUTH_GATE = {"807": FEATURE_GATE, "290": CSRF_IDENTITY}
# Possessive: matched on the owner line of a deny; `^\s*\}?\s*else` was
# quadratic on a long leading-whitespace line.
BARE_ELSE = re.compile(r"^\s*+\}?\s*+else\s*+[{:]?\s*+$")
# A READ of the caller's identity decides nothing by itself (a locale, metrics or
# tracing middleware reads it too). It is guard evidence only inside a NEGATED
# branch condition whose own body turns the request away.
IDENTITY_READ = re.compile(
    r"\bcurrent_user\b|\bcurrentUser\b|\bis_authenticated\b|\b[Ii]sAuthenticated\b"
    r"|\bgetSession\s*\(|\bgetServerSession\s*\(|\bgetToken\s*\(|(?<![\w.])auth\s*\(\s*\)"
    r"|(?<![\w.])authenticate\s*\("
)
_IDENT = (
    r"(?:current_user|currentUser|is_authenticated|[Ii]sAuthenticated"
    r"|getSession|getServerSession|getToken|auth\s*\(\s*\))"
)
NEGATED_IDENTITY = re.compile(
    rf"(?:!|\bnot\s)\s*(?:await\s+)?[\w$.]{{0,60}}{_IDENT}"
    rf"|{_IDENT}[\w$.()?]{{0,40}}\s*(?:===?\s*(?:null|undefined|nil|false)|\bis\s+None|==\s*None)"
)
# What the body of such a branch does to turn the request away, besides a deny.
SOFT_DENY = re.compile(r"\bredirect\w*\s*\(|\brewrite\s*\(|\breturn\s+(?:false|False)\b")
# RAW lines only: the keyword must sit INSIDE the call's first string literal
# (its opening quote, the keyword, its closing quote, all on one line). A
# closing quote followed by `auth` on a later line (the next function's name)
# is not a login target, and neither is an HTTPS / canonical-host redirect.
GUARD_REDIRECT = re.compile(
    r"""\b(?:redirect\w*|rewrite)\s*\([^)'"`]{0,200}?(?P<rq>['"`])"""
    r"""(?=[^'"`\n]{0,200}?(?:login|signin|sign-in|sign_in|auth))[^'"`\n]{0,200}+(?P=rq)""",
    re.IGNORECASE,
)
# RAW-only deny evidence: a login redirect / rewrite, a raw status line, the
# next-auth middleware re-export (`export { default } from "next-auth/middleware"`),
# or an auth module's guard re-exported as the middleware (Auth.js v5
# `export { auth as middleware } from "@/auth"`).
RAW_DENY = re.compile(
    rf"{GUARD_REDIRECT.pattern}|HTTP/1\.[01]\s+40[13]\b|\bfrom\s+['\"]next-auth/middleware['\"]"
    r"|\bexport\s*\{[^}\n]{0,80}?\b(?:default|middleware|proxy)\b[^}\n]{0,40}\}"
    r"""\s*from\s*['"][^'"\n]{0,120}?(?<![a-z])auth(?![a-z])""",
    re.IGNORECASE,
)
COND_KEY = re.compile(r"\b(?:missing|has)\s*:\s*\[")
ATTR_TYPE = re.compile(r"""\btype['"]?\s*:\s*['"](?P<kind>header|cookie|query)['"]""")
ATTR_KEY = re.compile(r"""\bkey['"]?\s*:\s*['"](?P<name>[^'"\n]{1,80})['"]""")
# A JSON-style quoted structural key (`"matcher": [`) is the same key; it is
# unquoted before strings are blanked so the code view still sees it.
_QUOTED_KEY = re.compile(r"""(['"])(matcher|missing|has)\1(?=\s*:)""")
# The variable form of MATCHER_KEY counts only when the file binds it into the
# config by shorthand (`config = { matcher }`): a `const matcher` of any other
# library is not a route matcher.
MATCHER_VAR = re.compile(r"\b(?:const|let|var)\s+matcher\b")
# The object may be wrapped across lines (Prettier keeps `{\n  matcher,\n}`).
CONFIG_SHORTHAND = re.compile(
    r"\bconfig\s*(?::[^=\n]{0,60})?=\s*\{[^}]{0,400}?(?<![\w.])matcher\s*[,}]"
)
# `params[:controller]` / `params[:action]` are set by the Rails router; a path
# parameter of the same name overrides the query, so they are not client input.
RAILS_ROUTER_KEY = re.compile(r"^(?:controller|action)$")
# An auth filter symbol; Rails' CSRF filters (`:verify_authenticity_token`,
# `:protect_from_forgery`) are not authentication guards.
AUTH_SYMBOL = re.compile(
    r":(?!\w{0,60}(?:authenticity|forgery|csrf))\w*(?:auth|login|sign_?in|verify|require_user)\w*[!?]?",
    re.IGNORECASE,
)
COND_OPTION = re.compile(r"\b(?:if|unless)\s*:")
HEADER_MATCHER = re.compile(r"RequestHeaderRequestMatcher\s*\(")
HEADER_MATCHER_NAME = re.compile(r"""RequestHeaderRequestMatcher\s*\(\s*['"](?P<name>[^'"\n]{1,80})['"]""")
# The header matcher must BE the argument of the permit rule, on the same chain:
# `requestMatchers(<m>).permitAll()`, `ignoring().requestMatchers(<m>)`, or the
# Kotlin DSL `authorize(<m>, permitAll)`. A matcher that feeds an entry point,
# `ignoringRequestMatchers` (CSRF) or anything else is not an auth exclusion.
_SPRING_MATCHERS = r"(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*(?:new\s+)?$"
SPRING_IGNORING_HEAD = re.compile(rf"\bignoring\s*\(\s*\)\s*\.\s*{_SPRING_MATCHERS}")
SPRING_ARG_HEAD = re.compile(rf"\b(?:{_SPRING_MATCHERS}|authorize\s*\(\s*$)")
SPRING_PERMIT_TAIL = re.compile(
    r"^RequestHeaderRequestMatcher\s*\([^()]{0,200}\)\s*(?:\)\s*\.\s*permitAll\s*\(|,\s*permitAll\b)"
)
_SPRING_REACH = 300
UNLESS_CUSTOM = re.compile(r"\bcustom\s*:")
UNLESS_CALL = re.compile(r"\.unless\s*\(")
# Echo `Skipper`, Fiber `Next`, gofiber/contrib jwtware `Filter`.
SKIPPER_FUNC = re.compile(r"\b(?:Skipper|Next|Filter)\s*:\s*func\s*\(")
SKIPPABLE_GUARD = re.compile(
    r"(?i:\b(?:expressjwt|jwt|echojwt|jwtware|keyauth|basicauth|requireAuth\w*"
    r"|passport\s*\.\s*authenticate)\b)"
    r"|\b(?:KeyAuth|BasicAuth|JWT)\w*"
)
# An inline branch (`if (x) return next();`, `if x: return`) has its body ON the
# line; only a header ending in `{`, `)` or `:` (or Allman) continues below.
OPEN_TAIL = re.compile(r"[{):]\s*$")
# `const bypass = <read>` / `String ua = <read>` / `$x = <read>` / `x := <read>`.
_ASSIGN = re.compile(
    r"^\s*(?:[\w<>\[\],.?]{1,40}\s+){0,2}\$?(?P<name>[A-Za-z_]\w{0,40})\s*"
    r"(?::\s*[\w.<>\[\]|]{1,40}\s*)?:?=(?!=)"
)
_INLINE_COLON = re.compile(r"^\s*(?:if|elif)\b[^{};()]{0,200}:\s*\S")
_SERVER_VAR = re.compile(r"\$_SERVER|\bMETA\b")
_LOOKBACK = 15
_ALIAS_WINDOW = 5
_TAIL_LIMIT = 30
_MATCHER_LIMIT = 40
_CONDITION_LIMIT = 12
_OWNER_LOOKBACK = 8
_RAILS_CONTINUATION = 2
_RAW_REACH = 3
# Multi-line literals and block comments, scanned over the whole file so a
# triple-quoted docstring, a template literal or an unprefixed `/* */` line is
# not read as code. Single-line strings and line comments are matched only so
# that a `/*` or a backtick INSIDE them does not open anything; they are left
# for the per-line strip. ReDoS: every body loop is possessive and every
# construct ALSO ends at end of file (a single-line string at end of line), so
# each opener is one linear match that always succeeds; an unclosed opener can
# never fail and be retried from the next offset (that retry is quadratic).
_MULTILINE = re.compile(
    r'"""(?:[^"\\]|\\.|"(?!""))*+\\?(?:"""|\Z)'
    r"|'''(?:[^'\\]|\\.|'(?!''))*+\\?(?:'''|\Z)"
    r"|`(?:[^`\\]|\\.)*+\\?(?:`|\Z)"
    r"|/\*(?:[^*]|\*(?!/))*+(?:\*/|\Z)"
    r'|"(?:[^"\\\n]|\\.)*+\\?(?:"|(?=\n)|\Z)'
    r"|'(?:[^'\\\n]|\\.)*+\\?(?:'|(?=\n)|\Z)"
    r"|//[^\n]*"
    r"|(?:^|(?<=\s))#[^\n]*",
    re.MULTILINE | re.DOTALL,
)
_NON_NEWLINE = re.compile(r"[^\n]")


# --- data ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FileView:
    """One file, raw and as code, plus the owning skill's authz predicates."""

    lines: Sequence[str]
    codes: tuple[str, ...]
    has_authz: Callable[[str], bool]
    role_patterns: Sequence[re.Pattern]

    @cached_property
    def raw_text(self) -> str:
        return "\n".join(self.lines)

    @cached_property
    def literal_names(self) -> frozenset[str]:
        """Identifiers bound in this file ONLY to non-placeholder literals.

        Computed once per file over the raw lines, and only when a comparand
        is an identifier. A name also bound to anything else (an env read, a
        config load after a placeholder, an import) is not in the set, and
        neither is a binding inside an open parenthesis (a parameter default
        on a wrapped parameter list, a keyword argument).
        """
        lit: set[str] = set()
        other: set[str] = set()
        stack: list[str] = []
        for line, code in zip(self.lines, self.codes):
            _enter_line(stack, code)
            _bind_line(line, code, other if stack[-1:] == ["("] else lit, other)
            _bind_reassignments(line, other)
            _push_brackets(stack, _brackets(code))
        return frozenset(lit - other)

    @cached_property
    def binds_matcher_shorthand(self) -> bool:
        """The file binds a ``matcher`` variable into its config by shorthand
        (a per-file fact, computed once)."""
        return CONFIG_SHORTHAND.search(self.raw_text) is not None

    @cached_property
    def rails_conditions(self) -> frozenset[tuple[str, bool]]:
        """``(condition, guard runs when it is true)`` of every Rails auth
        filter declaration with an ``if:`` / ``unless:`` in the file."""
        decls = (_rails_declaration(self, i) for i in range(len(self.codes)))
        return frozenset(p for d in decls if (p := _rails_polarity(d)))

    @cached_property
    def evidence_prefix(self) -> tuple[int, ...]:
        """Running count of guard-evidence lines: ``[k]`` counts lines ``< k``.

        Computed ONCE per file, so "is there evidence in lines a..b" is O(1)
        for every branch and every matcher (the per-matcher rescan was
        quadratic in file size).
        """
        flags = (guard_evidence_at(self, j) for j in range(len(self.codes)))
        return (0, *accumulate(int(f) for f in flags))

    def evidence_between(self, start: int, stop: int) -> int:
        """Number of guard-evidence lines in ``[start, stop)``."""
        n = len(self.codes)
        lo, hi = min(max(start, 0), n), min(max(stop, 0), n)
        return max(self.evidence_prefix[hi] - self.evidence_prefix[lo], 0)


@dataclass(frozen=True)
class ReadSite:
    """A client-attribute read that a branch condition depends on.

    ``operand`` / ``start`` / ``end`` locate the value the condition tests
    (the read itself, or the alias identifier) for the negation check;
    ``read_start`` / ``read_end`` locate the read itself in ``read_raw`` (the
    alias line, for an alias), whose own comparison veto 5 also reads.
    """

    kind: str
    name: str
    raw_name: str
    accessor: str
    read_raw: str
    cond_raw: str
    cond_code: str
    operand: str
    start: int
    end: int
    idx: int
    read_start: int
    read_end: int


@dataclass(frozen=True)
class GuardSite:
    """One row to emit: 0-based line, spec key (807 / 290 / excluded), detail."""

    idx: int
    key: str
    attr: str
    effect: str


@dataclass(frozen=True)
class DeclHit:
    """A declarative exclusion keyed on a client attribute: the attribute kind,
    its name match (``None`` when the hook names no attribute) and the raw
    text ``m`` was matched in (its offsets index that text)."""

    kind: str
    m: re.Match | None
    text: str


# --- code view and reads ------------------------------------------------------------
def _blank_multiline(m: re.Match) -> str:
    text = m.group(0)
    return _NON_NEWLINE.sub(" ", text) if "\n" in text else text


def mask_multiline(lines: Sequence[str]) -> list[str]:
    """The lines with every MULTI-line literal or block comment blanked to
    spaces (line count and columns kept); single-line constructs untouched."""
    return _MULTILINE.sub(_blank_multiline, "\n".join(lines)).split("\n")


def _code_line(line: str) -> str:
    if not line.strip() or COMMENT_INDICATORS.match(line):
        return ""
    return strip_strings_and_comments(_QUOTED_KEY.sub(r"\2", line))


def code_lines(lines: Sequence[str]) -> tuple[str, ...]:
    """Each line with strings and comments blanked ("" for a comment line, or a
    line wholly inside a docstring, template literal or block comment)."""
    return tuple(_code_line(line) for line in mask_multiline(lines))


def client_read(raw: str, code: str) -> tuple[str, re.Match] | None:
    """The first accessor whose root is in the code and whose name is in raw."""
    return next(
        ((kind, m) for kind, root, full in _ACC if root.search(code) and (m := full.search(raw))),
        None,
    )


def attr_name(m: re.Match) -> str:
    """Normalise ``HTTP_X_FOO`` to ``x-foo``; lower-case everything."""
    name = m.group("name")
    if name.upper().startswith("HTTP_"):
        return name[5:].lower().replace("_", "-")
    return name.lower()


def _site(kind: str, m: re.Match, read_raw: str, view: FileView, idx: int) -> ReadSite:
    return ReadSite(
        kind=kind, name=attr_name(m), raw_name=m.group("name"), accessor=m.group(0),
        read_raw=read_raw, cond_raw=view.lines[idx], cond_code=view.codes[idx],
        operand=read_raw, start=m.start(), end=m.end(), idx=idx,
        read_start=m.start(), read_end=m.end(),
    )


def _use_in_condition(view: FileView, idx: int, name: str) -> re.Match | None:
    """Where the condition at ``idx`` uses identifier ``name``.

    Presence is judged on code (not inside a string or comment); the position
    is taken on the raw line, so the negation check sees the real comparand
    rather than a blanked string.
    """
    ident = re.compile(rf"(?<![\w.$]){re.escape(name)}\b")
    return ident.search(view.lines[idx]) if ident.search(view.codes[idx]) else None


def _alias_at(view: FileView, idx: int, j: int) -> ReadSite | None:
    """``const x = <read>`` on line ``j`` whose ``x`` the condition at ``idx`` tests."""
    hit = client_read(view.lines[j], view.codes[j])
    am = _ASSIGN.match(view.codes[j]) if hit else None
    use = _use_in_condition(view, idx, am.group("name")) if am else None
    if use is None:
        return None
    site = _site(hit[0], hit[1], view.lines[j], view, idx)
    return replace(site, operand=view.lines[idx], start=use.start(), end=use.end())


def aliased_read(view: FileView, idx: int) -> ReadSite | None:
    """One-hop alias, nearest assignment first, within 5 lines above."""
    window = range(idx - 1, max(-1, idx - 1 - _ALIAS_WINDOW), -1)
    return next((s for j in window if (s := _alias_at(view, idx, j))), None)


def _resolve_read(view: FileView, idx: int) -> ReadSite | None:
    hit = client_read(view.lines[idx], view.codes[idx])
    if hit is None:
        return aliased_read(view, idx)
    return _site(hit[0], hit[1], view.lines[idx], view, idx)


# --- vetoes -------------------------------------------------------------------------
def attr_vetoed(kind: str, name: str) -> bool:
    """A credential, a neutral (format / locale / tracing / CORS) name, a
    gateway-injected identity, or a privilege cookie the cookie rule owns.
    Shared by the imperative and the declarative arms."""
    if kind == "cookie" and PRIV_COOKIE.match(name):
        return True
    return any(p.match(name) for p in (CREDENTIAL_ATTR, NEUTRAL_ATTR, GATEWAY_IDENTITY))


def _vetoed_attribute(site: ReadSite, view: FileView) -> bool:
    return attr_vetoed(site.kind, site.name)


def _owned_by_role_rule(site: ReadSite, view: FileView) -> bool:
    return any(p.search(site.cond_raw) or p.search(site.read_raw) for p in view.role_patterns)


def _second_argument(text: str, start: int, end: int) -> str:
    """``Objects.equals(<read>, X)``: ``X`` ("" for any other shape)."""
    if not _EQUALS_CALL_BEFORE.search(text[max(0, start - 200):start]):
        return ""
    m = _SECOND_ARG.match(text[end:])
    return m.group("c") if m else ""


def _comparand_before(text: str, start: int) -> str:
    m = _COMPARAND_BEFORE.search(text[max(0, start - 200):start])
    return m.group("c") if m else ""


def raw_comparand(text: str, start: int, end: int) -> str:
    """RAW text of the value the read at ``text[start:end]`` is equality-compared
    against ("" when the read is not an equality operand)."""
    after = _COMPARAND_AFTER.match(text[end:])
    if after:
        return after.group("c")
    return _second_argument(text, start, end) or _comparand_before(text, start)


def _enter_line(stack: list[str], code: str) -> None:
    """A top-level line closes every bracket still open above it."""
    if _TOP_LEVEL.match(code):
        stack.clear()


def _brackets(code: str) -> list[str]:
    """The brackets of ``code`` in order (a declaration group opens a block)."""
    return ["{"] if _DECL_GROUP.match(code) else _BRACKET.findall(code)


def _push_brackets(stack: list[str], brackets: list[str]) -> None:
    for ch in brackets:
        if ch in "({[":
            stack.append(ch)
        elif stack:
            stack.pop()


def _is_known_literal(rhs: str) -> bool:
    return _LIT_RHS.match(rhs) is not None and _PLACEHOLDER.match(rhs) is None


def _split_declarator(rhs: str, multi: bool) -> tuple[str, re.Match | None]:
    """The value of the first declarator in ``rhs`` and the next declarator."""
    nxt = _NEXT_DECLARATOR.match(rhs) if multi else None
    if nxt is None:
        return rhs, None
    return nxt.group("lit"), _DECL.match(nxt.group("rest"))


def _declarators(line: str) -> Iterator[tuple[str, str]]:
    """``(lhs, rhs)`` per declarator of a ``<lhs> = <rhs>`` line: after
    ``const`` / ``let`` / ``var``, ``A = 'x', B = 'y'`` is two (at most 16)."""
    m = _DECL.match(line)
    multi = m is not None and _DECL_KEYWORD.search(m.group("lhs")) is not None
    for _ in range(_MAX_DECLARATORS):
        if m is None:
            return
        value, nxt = _split_declarator(m.group("rhs"), multi)
        yield m.group("lhs"), value
        m = nxt


def _qualified_members(names: list[str], body: str) -> list[str]:
    """``name.key`` for each ``key: <literal>`` member of an object literal body."""
    keys = [m.group("key") for m in _LIT_MEMBER.finditer(body)]
    return [f"{name}.{key}" for name in names for key in keys]


def _bind_value(names: list[str], rhs: str, lit: set[str], other: set[str]) -> None:
    """``names`` into ``lit`` when ``rhs`` is a non-placeholder literal, else
    into ``other``; the ``key: <literal>`` members of an object literal into
    ``lit`` as ``name.key``."""
    obj = _OBJECT_RHS.match(rhs)
    if obj is not None:
        lit.update(_qualified_members(names, obj.group("body")))
    (lit if _is_known_literal(rhs) else other).update(names)


def _bind_decl(line: str, lit: set[str], other: set[str]) -> None:
    """Record the names a ``<lhs> = <rhs>`` line binds."""
    for lhs, rhs in _declarators(line):
        _bind_value(_DECL_NAME.findall(lhs), rhs, lit, other)


def _bind_define(m: re.Match, lit: set[str], other: set[str]) -> None:
    """PHP ``define('NAME', <value>)``: ``lit`` only for a non-placeholder literal."""
    value = m.group("lit")
    known = value is not None and _PLACEHOLDER.match(value) is None
    (lit if known else other).add(m.group("name"))


def _bind_line(line: str, code: str, lit: set[str], other: set[str]) -> None:
    """An import binds its names to ``other``; a PHP ``define`` and a
    declaration as above."""
    imp = _IMPORT.match(code)
    if imp is not None:
        other.update(_DECL_NAME.findall(imp.group("names")))
        return
    define = _DEFINE.match(line)
    if define is not None:
        _bind_define(define, lit, other)
        return
    _bind_decl(line, lit, other)


def _bind_reassignments(line: str, other: set[str]) -> None:
    """Every name assigned anywhere on ``line`` a value that does not start
    with a literal goes to ``other``."""
    other.update(m.group("name") for m in _ANY_ASSIGN.finditer(line)
                 if not _LIT_START.match(line, m.end()))


def _ident_keys(m: re.Match) -> tuple[str, ...]:
    """The names a comparand identifier resolves by: its last segment, and
    ``Qualifier.last`` (an object literal's member)."""
    qualifier = m.group("q2") or m.group("q1")
    return (m.group("id"), f"{qualifier}.{m.group('id')}") if qualifier else (m.group("id"),)


def _bound_to_literal(c: str, view: FileView) -> bool:
    ident = COMPARAND_IDENT.match(c)
    return ident is not None and not view.literal_names.isdisjoint(_ident_keys(ident))


def is_client_knowable(c: str, view: FileView) -> bool:
    """A literal that is the whole comparand; another request read (the
    client sets both sides); or an identifier bound in this file only to
    non-placeholder literals, also as an enum member's ``.value`` / ``.name``."""
    if LITERAL_COMPARAND.match(c) or CLIENT_READ.match(c):
        return True
    return any(_bound_to_literal(x, view) for x in (c, _ENUM_VALUE.sub("", c, count=1)))


def compared_to_server_value(name: str, text: str, start: int, end: int, view: FileView) -> bool:
    """Equality with a value the client cannot know (an env or config value, a
    field, a call result, an imported constant) is a shared secret, i.e.
    AUTHENTICATION, not a bypass. Not for identity attributes: a forged XFF
    matches a configured list too."""
    if IDENTITY_ATTR.match(name):
        return False
    c = raw_comparand(text, start, end).strip()
    return bool(c) and not is_client_knowable(c, view)


def _compares_server_value(site: ReadSite, view: FileView) -> bool:
    """Veto 5 on the condition, or, for an alias, on the alias line itself
    (``const ok = <read> === process.env.T; if (ok)``)."""
    if compared_to_server_value(site.name, site.operand, site.start, site.end, view):
        return True
    return compared_to_server_value(site.name, site.read_raw, site.read_start, site.read_end, view)


def verified_conjunct(code: str) -> bool:
    """A verifying call conjoined with the read, not negated."""
    return any(not m.group("neg") for m in VERIFIED_CONJUNCT.finditer(code))


def _has_verifier(site: ReadSite, view: FileView) -> bool:
    """A verifying call conjoined with the read in the condition, or a
    signature verifier in the condition or in the branch's own body."""
    if verified_conjunct(view.codes[site.idx]):
        return True
    return VERIFIER.search("\n".join(branch_body(view.codes, site.idx))) is not None


def _is_negated(site: ReadSite, view: FileView) -> bool:
    before = site.operand[: site.start].rstrip()
    return bool(NEG_BEFORE.search(before) or NEG_AFTER.search(site.operand[site.end:]))


def _is_non_header_server_var(site: ReadSite, view: FileView) -> bool:
    """``$_SERVER`` / ``request.META`` qualify only for client ``HTTP_*`` names."""
    return bool(_SERVER_VAR.search(site.accessor)) and not site.raw_name.upper().startswith("HTTP_")


_VETOES = (
    _vetoed_attribute, _owned_by_role_rule, _compares_server_value, _has_verifier,
    _is_negated, _is_non_header_server_var,
)


def is_vetoed(site: ReadSite, view: FileView) -> bool:
    return any(veto(site, view) for veto in _VETOES)


# --- branch outcome -----------------------------------------------------------------
def branch_body(codes: Sequence[str], idx: int) -> list[str]:
    """The branch header plus its own body (inline: the header line only)."""
    head = codes[idx]
    if not OPEN_TAIL.search(head):
        return [head]
    brace = not head.rstrip().endswith(":")
    return [head, *collect_scoped_body(codes, idx + 1, brace, max_body_lines=3)]


def _above(view: FileView, idx: int, pattern: re.Pattern) -> bool:
    """``pattern`` on a non-comment raw line within 15 lines above ``idx``."""
    start = max(0, idx - _LOOKBACK)
    return any(view.codes[j] and pattern.search(view.lines[j]) for j in range(start, idx))


@dataclass(frozen=True)
class _Branch:
    view: FileView
    idx: int
    parts: list[str]

    @property
    def text(self) -> str:
        return "\n".join(self.parts)


def _skip_returning(b: _Branch) -> bool:
    return SKIP_RETURNING.search(b.text) is not None


def _skip_call(b: _Branch) -> bool:
    return bool(SKIP_CALL.search(b.text)) and any(RETURN_STMT.search(p) for p in b.parts)


def _skip_else(b: _Branch) -> bool:
    """`if (x) { next(); } else ...`: the else carries the guard. Only the
    lines BEFORE the `} else` belong to this branch."""
    cut = next((i for i, part in enumerate(b.parts) if ELSE_TAIL.search(part)), None)
    return cut is not None and SKIP_CALL.search("\n".join(b.parts[:cut])) is not None


def _hook_return(b: _Branch) -> bool:
    return any(BARE_RETURN.search(p) for p in b.parts) and _above(b.view, b.idx, PRE_HOOK)


def _succeed(b: _Branch) -> bool:
    return GRANT_SUCCEED.search(b.text) is not None


def _return_true_in_guard(b: _Branch) -> bool:
    return bool(GRANT_RETURN_TRUE.search(b.text)) and _above(b.view, b.idx, GUARD_FN)


def _grant_flag(b: _Branch) -> bool:
    return GRANT_FLAG.search(b.text) is not None


def _return_true_in_interceptor(b: _Branch) -> bool:
    return bool(GRANT_RETURN_TRUE.search(b.text)) and _above(b.view, b.idx, INTERCEPTOR_FN)


def _principal(b: _Branch) -> bool:
    return PRINCIPAL_RETURN.search(b.text) is not None and _above(b.view, b.idx, PRINCIPAL_PROVIDER)


# Ordered: the first outcome that holds labels the branch.
_OUTCOMES = (
    ("skip", _skip_returning), ("skip", _skip_call), ("skip", _skip_else), ("skip", _hook_return),
    ("grant_intrinsic", _succeed), ("grant_intrinsic", _return_true_in_guard),
    ("skip", _return_true_in_interceptor),
    ("grant", _grant_flag), ("grant", _principal),
)


def branch_outcome(view: FileView, idx: int) -> str | None:
    branch = _Branch(view, idx, branch_body(view.codes, idx))
    return next((label for label, holds in _OUTCOMES if holds(branch)), None)


# --- guard evidence in the enclosing scope ------------------------------------------
def _is_indent_scope(code: str) -> bool:
    return code.rstrip().endswith(":") or _INLINE_COLON.match(code) is not None


def _indent(code: str) -> int:
    return len(code) - len(code.lstrip())


def _brace_tail(codes: Sequence[str], idx: int, stop: int) -> int:
    depth = 0
    for j in range(idx, stop):
        depth += codes[j].count("{") - codes[j].count("}")
        if depth < 0:
            return j
    return stop


def _indent_tail(codes: Sequence[str], idx: int, stop: int) -> int:
    base = _indent(codes[idx])
    return next(
        (j for j in range(idx + 1, stop) if codes[j].strip() and _indent(codes[j]) < base),
        stop,
    )


def tail_end(codes: Sequence[str], idx: int, limit: int = _TAIL_LIMIT) -> int:
    """Exclusive end of the ENCLOSING scope after the branch at ``idx``.

    Brace family: the line where the running depth drops below 0. Indent
    family: the first non-blank line indented less than the branch.
    """
    stop = min(len(codes), idx + limit)
    if _is_indent_scope(codes[idx]):
        return _indent_tail(codes, idx, stop)
    return _brace_tail(codes, idx, stop)


def _raw_text(view: FileView, indices: Iterator[int] | range) -> str:
    return "\n".join(view.lines[j] for j in indices if view.codes[j])


def _raw_deny_at(view: FileView, j: int) -> bool:
    """A raw-only deny that STARTS on line ``j`` (it may run onto the next lines)."""
    m = RAW_DENY.search(_raw_text(view, range(j, min(len(view.lines), j + _RAW_REACH))))
    return m is not None and m.start() <= len(view.lines[j])


def _denies(view: FileView, code: str) -> bool:
    """A deny on code. Identity reads are blanked first so that the owning
    skill's ``has_authz`` (which knows ``IsAuthenticated``) cannot count one."""
    return bool(GUARD_EVIDENCE.search(code) or view.has_authz(IDENTITY_READ.sub(" ", code)))


def _identity_guard_at(view: FileView, j: int) -> bool:
    """`if (!currentUser) <turn away>`: a negated identity test whose own body denies."""
    code = view.codes[j]
    if not (BRANCH.search(code) and NEGATED_IDENTITY.search(code)):
        return False
    body = "\n".join(branch_body(view.codes, j))
    return bool(SOFT_DENY.search(body) or _denies(view, body))


def guard_evidence_at(view: FileView, j: int) -> bool:
    """Line ``j`` carries guard evidence: a deny, a raw login redirect / status
    line, or a negated identity test whose body turns the request away."""
    if not view.codes[j]:
        return False
    return _denies(view, view.codes[j]) or _raw_deny_at(view, j) or _identity_guard_at(view, j)


def _guard_follows(view: FileView, idx: int) -> bool:
    return view.evidence_between(idx + 1, tail_end(view.codes, idx)) > 0


def _owner(codes: Sequence[str], j: int, floor: int) -> int:
    """Nearest non-blank line above ``j`` (not above ``floor``) indented less
    than ``j``; ``floor - 1`` when there is none."""
    base = _indent(codes[j])
    above = range(j - 1, floor - 1, -1)
    return next((k for k in above if codes[k].strip() and _indent(codes[k]) < base), floor - 1)


def _named_guard(view: FileView, j: int) -> bool:
    """A guard call, or a deny that says AUTHENTICATION (a 401, a login
    redirect): either one is a guard of its own, wherever it sits."""
    code = view.codes[j]
    if NAMED_GUARD.search(code) or AUTHN_DENY.search(code) or GUARD_REDIRECT.search(view.lines[j]):
        return True
    return view.has_authz(IDENTITY_READ.sub(" ", code))


def _conditional(view: FileView, idx: int, j: int) -> bool:
    """Line ``j`` sits under a condition of its own, not under the branch at
    ``idx`` or that branch's bare ``else``."""
    if BRANCH.search(view.codes[j]):
        return True
    owner = _owner(view.codes, j, idx)
    return owner > idx and not BARE_ELSE.match(view.codes[owner])


def _independent_evidence(view: FileView, idx: int, j: int) -> bool:
    if not view.evidence_between(j, j + 1):
        return False
    return _named_guard(view, j) or _conditional(view, idx, j)


def _independent_guard_follows(view: FileView, idx: int) -> bool:
    """A guard that does NOT merely restate the branch: a named guard, a 401
    or login redirect, or a deny under a condition of its own. An
    unconditional 403 that is the branch's own fall-through makes the
    attribute the gate itself."""
    tail = range(idx + 1, tail_end(view.codes, idx))
    return any(_independent_evidence(view, idx, j) for j in tail)


# --- arm I: imperative --------------------------------------------------------------
_EFFECT = {"skip": "SKIPPED", "grant": "SATISFIED", "grant_intrinsic": "SATISFIED"}


def _label(site: ReadSite) -> str:
    return f"{site.kind} `{site.raw_name}`"


def _is_compared(site: ReadSite) -> bool:
    """Compared, prefix-matched, or used as a lookup key (`trusted[<read>]`)."""
    keyed = INDEXED_BY.search(site.operand[max(0, site.start - 80):site.start])
    return bool(COMPARISON.search(site.cond_code) or keyed)


def _spec_key(site: ReadSite) -> str | None:
    """290 for a compared identity attribute, none for identity presence, else 807."""
    if not IDENTITY_ATTR.match(site.name):
        return "807"
    return "290" if _is_compared(site) else None


def _needs_independent_guard(site: ReadSite, key: str) -> bool:
    """A gate on an attribute named as a feature, challenge or selection gate
    (any kind: header, query, body or cookie), or a Referer (CSRF) check, is
    not an auth decision by itself."""
    gate = _NON_AUTH_GATE.get(key)
    return gate is not None and gate.match(site.name) is not None


def _outcome_applies(view: FileView, idx: int, outcome: str, site: ReadSite, key: str) -> bool:
    """An intrinsic grant is a guard decision by itself; anything else needs
    guard evidence after it in the enclosing scope (an INDEPENDENT guard for a
    feature-gate attribute)."""
    if outcome == "grant_intrinsic":
        return True
    follows = _independent_guard_follows if _needs_independent_guard(site, key) else _guard_follows
    return follows(view, idx)


def _classify(view: FileView, idx: int, site: ReadSite) -> GuardSite | None:
    outcome, key = branch_outcome(view, idx), _spec_key(site)
    if outcome is None or key is None or not _outcome_applies(view, idx, outcome, site, key):
        return None
    return GuardSite(idx, key, _label(site), _EFFECT[outcome])


def imperative_site(view: FileView, idx: int) -> GuardSite | None:
    """The row a branch at ``idx`` earns, if any."""
    site = _resolve_read(view, idx) if BRANCH.search(view.codes[idx]) else None
    if site is None or is_vetoed(site, view):
        return None
    return _classify(view, idx, site)


def _imperative_sites(view: FileView) -> list[GuardSite]:
    return [s for i in range(len(view.codes)) if (s := imperative_site(view, i))]


# --- arm II: route-matcher exclusion ------------------------------------------------
def _segments(codes: Sequence[str], idx: int, stop: int) -> Iterator[str]:
    """The code lines from ``idx``; the first one starts after a ``matcher:`` key."""
    key = MATCHER_KEY.search(codes[idx])
    first = codes[idx][key.end():] if key else codes[idx]
    return chain((first,), codes[idx + 1:stop])


def _opens(seg: str) -> bool:
    return "[" in seg or "{" in seg


def _closed(opened: bool, depth: int) -> bool:
    return opened and depth <= 0


def bracket_span(codes: Sequence[str], idx: int, limit: int) -> int:
    """Last line (0-based, inclusive) of the bracket group opened at ``idx``.

    Balances ``[ {`` against ``] }`` on code, starting after a ``matcher:`` key
    when the line carries one. Capped at ``limit`` lines.
    """
    stop = min(len(codes), idx + limit)
    depth, opened = 0, False
    for j, seg in enumerate(_segments(codes, idx, stop), start=idx):
        depth += seg.count("[") + seg.count("{") - seg.count("]") - seg.count("}")
        opened |= _opens(seg)
        if _closed(opened, depth):
            return j
    return stop - 1


def _condition_text(view: FileView, k: int) -> str:
    """Raw text of the ``has`` / ``missing`` array at ``k`` (non-comment lines)."""
    return _raw_text(view, range(k, bracket_span(view.codes, k, _CONDITION_LIMIT) + 1))


def _first_condition(view: FileView, start: int, end: int) -> int | None:
    """First typed ``has`` / ``missing`` condition inside the matcher span."""
    return next(
        (k for k in range(start, end + 1)
         if COND_KEY.search(view.codes[k]) and ATTR_TYPE.search(_condition_text(view, k))),
        None,
    )


def _module_guarded(view: FileView, start: int, end: int) -> bool:
    """Guard evidence in the module OUTSIDE the matcher span."""
    total = view.evidence_between(0, len(view.codes))
    return total - view.evidence_between(start, end + 1) > 0


def _matcher_label(view: FileView, k: int) -> str:
    text = _condition_text(view, k)
    kind = ATTR_TYPE.search(text).group("kind")
    key = ATTR_KEY.search(text)
    return f"{kind} `{key.group('name')}`" if key else kind


def _matcher_key(view: FileView, idx: int) -> bool:
    """A ``matcher:`` key, or a ``const matcher =`` the file binds into its
    config by shorthand."""
    code = view.codes[idx]
    if not MATCHER_KEY.search(code):
        return False
    return not MATCHER_VAR.search(code) or view.binds_matcher_shorthand


def _matcher_site(view: FileView, idx: int) -> GuardSite | None:
    if not _matcher_key(view, idx):
        return None
    end = bracket_span(view.codes, idx, _MATCHER_LIMIT)
    k = _first_condition(view, idx, end)
    if k is None or not _module_guarded(view, idx, end):
        return None
    return GuardSite(k, "excluded", _matcher_label(view, k), "EXCLUDED")


def matcher_condition_lines(view: FileView) -> list[GuardSite]:
    """One row per ``matcher:`` whose span holds a typed client condition."""
    return [s for i in range(len(view.codes)) if (s := _matcher_site(view, i))]


# --- arm III: other declarative exclusions ------------------------------------------
def _window(view: FileView, start: int, stop: int) -> str:
    return "\n".join(view.codes[max(0, start):stop])


def _with_text(hit: tuple[str, re.Match] | None, text: str) -> DeclHit | None:
    """A client read as a :class:`DeclHit`, with the text it was matched in."""
    return DeclHit(hit[0], hit[1], text) if hit else None


def _read_ahead(view: FileView, idx: int) -> DeclHit | None:
    """The client read in a hook function that starts at ``idx`` (4 lines)."""
    text = "\n".join(view.lines[idx:idx + 4])
    return _with_text(client_read(text, _window(view, idx, idx + 4)), text)


def _unless_router_key(hit: DeclHit | None) -> DeclHit | None:
    """``hit`` unless it reads a router-set ``params[:controller|action]``."""
    if hit is None or not hit.m.group(0).startswith("params"):
        return hit
    return None if RAILS_ROUTER_KEY.match(attr_name(hit.m)) else hit


def _continuation_stop(codes: Sequence[str], idx: int) -> int:
    """Exclusive end of the declaration at ``idx``: up to 2 continuation lines
    while a line ends in ``,`` (``before_action :auth,`` / ``unless: ...``)."""
    stop = idx + 1
    limit = min(len(codes), idx + 1 + _RAILS_CONTINUATION)
    while stop < limit and codes[stop - 1].rstrip().endswith(","):
        stop += 1
    return stop


def _rails_declaration(view: FileView, idx: int) -> tuple[str, str] | None:
    """``(raw, code)`` of a Rails auth filter declaration at ``idx`` with an
    ``if:`` / ``unless:`` option, joined over its continuation lines."""
    if not (RAILS_FILTER.search(view.codes[idx]) and AUTH_SYMBOL.search(view.codes[idx])):
        return None
    stop = _continuation_stop(view.codes, idx)
    code = " ".join(view.codes[idx:stop])
    return (" ".join(view.lines[idx:stop]), code) if COND_OPTION.search(code) else None


def _rails_polarity(decl: tuple[str, str] | None) -> tuple[str, bool] | None:
    """``(condition text, the guard RUNS when the condition is true)`` of a
    declaration ``(raw, code)``."""
    raw, code = decl or ("", "")
    opt = COND_OPTION.search(raw)
    if opt is None:
        return None
    skip = RAILS_FILTER.search(code).group(0).startswith("skip_")
    return " ".join(raw[opt.end():].split()), opt.group(0).startswith("if") != skip


def _complemented(view: FileView, raw: str, code: str) -> bool:
    """Another auth filter runs exactly when this one does not (the same
    condition, the opposite polarity): the pair chooses between two
    authentication methods, so no request reaches the action unauthenticated."""
    polarity = _rails_polarity((raw, code))
    return polarity is not None and (polarity[0], not polarity[1]) in view.rails_conditions


def _rails_skip(view: FileView, idx: int) -> DeclHit | None:
    """``skip_before_action :auth, if:`` or ``before_action :auth, unless:``."""
    decl = _rails_declaration(view, idx)
    if decl is None or _complemented(view, *decl):
        return None
    raw, code = decl
    return _unless_router_key(_with_text(client_read(raw, code), raw))


def _spring_permits(head: str, tail: str) -> bool:
    if SPRING_IGNORING_HEAD.search(head):
        return True
    return bool(SPRING_ARG_HEAD.search(head) and SPRING_PERMIT_TAIL.match(tail))


def _spring_header_permit(view: FileView, idx: int) -> DeclHit | None:
    m = HEADER_MATCHER.search(view.codes[idx])
    if m is None:
        return None
    head = " ".join((*view.codes[max(0, idx - 2):idx], view.codes[idx][:m.start()]))
    tail = " ".join((view.codes[idx][m.start():], *view.codes[idx + 1:idx + 3]))
    if not _spring_permits(head[-_SPRING_REACH:], tail[:_SPRING_REACH]):
        return None
    return DeclHit("header", HEADER_MATCHER_NAME.search(view.lines[idx]), view.lines[idx])


def _unless_custom(view: FileView, idx: int) -> DeclHit | None:
    above = _window(view, idx - 3, idx + 1)
    if not (UNLESS_CUSTOM.search(view.codes[idx]) and UNLESS_CALL.search(above)):
        return None
    return _read_ahead(view, idx) if SKIPPABLE_GUARD.search(above) else None


def _segments_up(view: FileView, idx: int, col: int) -> Iterator[str]:
    """Line ``idx`` up to column ``col``, then the lines above it, nearest first."""
    above = range(idx - 1, max(-1, idx - 1 - _OWNER_LOOKBACK), -1)
    return chain((view.codes[idx][:col],), (view.codes[j] for j in above))


def _owner_text(view: FileView, idx: int, col: int) -> str:
    """The line holding the nearest UNBALANCED opener above column ``col`` of
    line ``idx``: the config literal (or call) that owns a hook declared there."""
    depth = 0
    for seg in _segments_up(view, idx, col):
        depth += seg.count(")") + seg.count("}") - seg.count("(") - seg.count("{")
        if depth < 0:
            return seg
    return ""


def _skipper_func(view: FileView, idx: int) -> DeclHit | None:
    m = SKIPPER_FUNC.search(view.codes[idx])
    if m is None or not SKIPPABLE_GUARD.search(_owner_text(view, idx, m.start())):
        return None
    return _read_ahead(view, idx)


_DECLARATIONS = (_rails_skip, _spring_header_permit, _unless_custom, _skipper_func)


def _declared_label(hit: DeclHit) -> str:
    return f"{hit.kind} `{hit.m.group('name')}`" if hit.m else hit.kind


def _declared_vetoed(hit: DeclHit, view: FileView) -> bool:
    """The attribute vetoes of the imperative arm, a verifier (a constant-time
    compare) in the hook, and veto 5 (a comparand the client cannot know) on
    the hook's own condition."""
    if hit.m is None:
        return False
    name = attr_name(hit.m)
    if attr_vetoed(hit.kind, name) or VERIFIER.search(hit.text):
        return True
    return compared_to_server_value(name, hit.text, hit.m.start(), hit.m.end(), view)


def _declared_hit(view: FileView, idx: int) -> DeclHit | None:
    return next((h for decl in _DECLARATIONS if (h := decl(view, idx))), None)


def _declaration_site(view: FileView, idx: int) -> GuardSite | None:
    hit = _declared_hit(view, idx)
    if hit is None or _declared_vetoed(hit, view):
        return None
    return GuardSite(idx, "excluded", _declared_label(hit), "EXCLUDED")


def declarative_exclusion_lines(view: FileView) -> list[GuardSite]:
    """One row per framework exclusion declaration keyed on a client attribute."""
    return [s for i in range(len(view.codes)) if (s := _declaration_site(view, i))]


# --- entry ----------------------------------------------------------------------
def guard_sites(view: FileView) -> list[GuardSite]:
    """Every row of the three arms, at most one per (line, spec key), in line order."""
    found = chain(_imperative_sites(view), matcher_condition_lines(view),
                  declarative_exclusion_lines(view))
    unique = {(s.idx, s.key): s for s in found}
    return sorted(unique.values(), key=lambda s: (s.idx, s.key))
