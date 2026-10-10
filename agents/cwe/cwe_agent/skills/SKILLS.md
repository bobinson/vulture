# CWE Weakness Auditor - Skills

Analyzes source code for Common Weakness Enumeration (CWE v4.19.1) vulnerabilities. The deterministic skill phase detects 171 declared CWE-ID `category` literals across 24 dedicated skills plus 7 corpus-trusted signature CWEs; of those, N=81 CWE types are corpus-VERIFIED (recall 1.0 / fp 0.0 — see `tests/corpus/VERIFIED_CWES.md`, computed by the gate, not asserted). The 846-entry CWE v4.19.1 catalog is metadata/context (names, consequences, rollup parents) — NOT a detection-coverage claim; it drives self-learning confidence scoring and MMR-based memory retrieval with embedding similarity.

## injection_check

- **Function**: `check_injection(source_path: str) -> dict`
- **Purpose**: Detects code injection vulnerabilities across SQL, OS command, XSS, dynamic code execution, and SSRF
- **CWE Coverage**:
  - **CWE-89** SQL Injection: f-string/format SQL queries, Sprintf-based queries
  - **CWE-78** OS Command Injection: `os.system()`, `os.popen()`, `subprocess` with `shell=True`, Go `exec.Command("sh"…)`; **and (feature 0060)** Java `Runtime.getRuntime().exec()` / `new ProcessBuilder()`, PHP `shell_exec`/`passthru`/`proc_open` and language-scoped bare `system()` (PHP/Ruby only) — moved here from `dangerous_function_check`
  - **CWE-79** Cross-Site Scripting: `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`
  - **CWE-94** Code Injection: `eval()`, `exec()`, `new Function()`, string-based `setTimeout`/`setInterval`
  - **CWE-918** Server-Side Request Forgery (SSRF): `requests.get(user_input)`, `urllib.request.urlopen(user_input)`, `http.Get(user_input)`, `fetch(user_input)`
- **Severity**: critical (CWE-89, CWE-78, CWE-94), high (CWE-79, CWE-918)
- **Detection**: Regex pattern matching with safe-call exclusions (static string arguments, import lines, URL allowlists)
- **Catalog Enrichment**: All findings enriched with CWE catalog metadata (name, likelihood, mitigation)

## buffer_check

- **Function**: `check_buffer_handling(source_path: str) -> dict`
- **Purpose**: Detects buffer handling vulnerabilities in C/C++/Go code including use-after-free and integer overflow
- **CWE Coverage**:
  - **CWE-120** Buffer Overflow: `strcpy`, `strcat`, `sprintf`, `gets`, `wcscpy`, `wcscat`
  - **CWE-787** Out-of-Bounds Write: `memcpy`/`memmove` without `sizeof` validation
  - **CWE-125** Out-of-Bounds Read: Array access without bounds checking (excludes constant indices)
  - **CWE-416** Use After Free: `free()` followed by pointer dereference within 5 lines
  - **CWE-190** Integer Overflow: Unchecked integer arithmetic, `malloc(count * size)` without overflow guard
- **Severity**: critical (CWE-120, CWE-416), high (CWE-787, CWE-190), medium (CWE-125)
- **Detection**: Regex patterns on C/C++/Go files only; excludes bounded alternatives and overflow checks

## auth_check

- **Function**: `check_authentication(source_path: str) -> dict`
- **Purpose**: Detects authentication weaknesses including hardcoded secrets and missing auth
- **CWE Coverage**:
  - **CWE-798** Hardcoded Credentials: passwords, API keys, tokens, secrets in string literals
  - **CWE-287** Improper Authentication: MD5/SHA1 password hashing, direct password comparison
  - **CWE-306** Missing Authentication: Route handlers without auth decorators/middleware
  - **CWE-521** Weak Password Requirements: Minimum length under 6 characters
- **Severity**: critical (CWE-798), high (CWE-287, CWE-306), medium (CWE-521)
- **Detection**: Pattern matching with safe-value exclusions (env vars, placeholders, test values)

## crypto_check

- **Function**: `check_cryptography(source_path: str) -> dict`
- **Purpose**: Detects cryptographic weaknesses across algorithms, key sizes, randomness, and hashing
- **CWE Coverage**:
  - **CWE-327** Broken Cryptographic Algorithm: DES, RC4, Blowfish, 3DES, ECB mode
  - **CWE-326** Inadequate Encryption Strength: RSA keys under 2048 bits
  - **CWE-330** Insufficient Randomness: `random.random()`, `Math.random()`, `rand()`
  - **CWE-328** Reversible One-Way Hash: MD5/SHA1 for integrity (excludes checksum/cache/HMAC)
- **Severity**: critical (CWE-327, hardcoded keys), high (CWE-326, CWE-330), medium (CWE-328)
- **Detection**: Pattern matching with context-aware exclusions

## input_validation_check

- **Function**: `check_input_validation(source_path: str) -> dict`
- **Purpose**: Detects input validation failures including path traversal, XXE, CSRF, and deserialization
- **CWE Coverage**:
  - **CWE-22** Path Traversal: `os.path.join` with user input, `../` patterns
  - **CWE-20** Improper Input Validation: Direct request data access without validation
  - **CWE-434** Unrestricted File Upload: File upload without type/size validation
  - **CWE-611** XML External Entity (XXE): XML parsing without entity restriction
  - **CWE-352** Cross-Site Request Forgery (CSRF): POST/PUT/DELETE without CSRF token
  - **CWE-502** Deserialization of Untrusted Data: `pickle.loads`, unsafe `yaml.load`
- **Severity**: critical (CWE-502), high (CWE-22, CWE-352, CWE-434, CWE-611), medium (CWE-20)
- **Detection**: Context window scanning with safe-alternative exclusions

## resource_check

- **Function**: `check_resource_management(source_path: str) -> dict`
- **Purpose**: Detects resource management issues including leaks, null dereferences, and unbounded allocations
- **CWE Coverage**:
  - **CWE-400** Uncontrolled Resource Consumption: Infinite loops
  - **CWE-404** Improper Resource Shutdown: Open without close/defer/with
  - **CWE-476** NULL Pointer Dereference: No nil check after call
  - **CWE-770** Allocation Without Limits: Unbounded appends/makes
  - **CWE-799** Improper Control of Interaction Frequency:
    - `cwe.resource.rate_limit` / `cwe.resource.express_rate_limit`: a login/register-style endpoint with no limiter in the file (def form) or on its route (Express form).
    - `cwe.resource.anonymous_message_send` (feature 0099): a caller with no authenticated principal makes the server send a message (e-mail, SMS, OTP, magic link, invitation) to a recipient the CALLER chose, and no human-verification step gates it. A mail-bombing / spam-relay vector: a quota keyed on the source or the recipient does not bound it, because both rotate. Framework-free: one implementation for every language, from identifier meaning and data flow:
      - send call: the callee starts with a delivery verb (`send`, `deliver`, `dispatch`, `notify`) and the call names a message (`sendPasswordlessEmail`, `send_sms_code`, `mailer.send`);
      - recipient: a recipient-named key (`to`, `recipient`, `email`, `phone`), else the first contact-shaped argument; sender-side names (`from`, `reply_to`, `cc`, `support`) are skipped. The recipient must be an ADDRESS: the call names an address channel (mail, SMS, OTP, magic link) or a contact-shaped name (email, phone) is on its chain, so a chat channel or a queue passed as `to` is not one;
      - caller-chosen: walking assignments back from the recipient inside the handler (call arguments included, and one hop into a same-file helper it calls) reaches a read of request input — a `body` / `query` / `form` receiver or property, `params[...]`, an HTTP-method container, or a parameter whose own annotation or type says body / form / query. A query RESULT type is not request input (0074): a capitalised compound type with `query` after its first word, when it is indexed into (`GetOrderByIdQuery["order"]`), followed by `result` / `row` (`ListOrdersQueryResult`), or — like a bare `...Query`, `...QueryData`, `...QueryResponse` — declares a parameter of a helper its own file calls (declared once) in an argument position no call passes request input in: as the caller holds it, a read, a body/form/query-named value, the caller's own request parameter, or a local copied from one (a converted copy counts; a row LOOKED UP with request input does not). An entry point's `InviteQuery`, `Query()` / `FromQuery` / `ReqQuery` bindings and every parameter NAME (`searchQuery`, `search_query`) stay request input. A record looked up BY the caller's address is still caller-chosen;
      - no gate: no authenticated principal and no human check that GATES the send — a branch that exits within four lines, or an asserting call (`requireUser()`), in the handler or that helper; or a decorator / annotation / attribute on it or its container, or a registration / wrapper line naming it. A shared secret verified AGAINST THE REQUEST gates too (0074): a call (a method call or one spread over several lines included) named for verifying a secret or a hook / webhook / shared token or key, with the secret as what is verified (`requireValidHookSecret`, `verify_webhook_secret`, `isSecretValid`, `verifyHookToken`; not `validateSecretMessage`), given the request itself — an argument whose root is `req` / `request` / `ctx` / `context` / `headers` or a parameter the handler declares as the request, never a body-bound parameter or a compound such as `requestId` — when that call is the branch-and-exit or the asserting statement, or is bound to a name a later branch exits on. A check of a submitted VALUE (a body / form / query field, a local holding one, a body-bound DTO: a secret-sharing or password-policy check) is content validation and does not gate; neither does a secret that is only read or logged, one verified after the send, a `must…` config read, or an anti-forgery (`csrf` / `xsrf`) secret. Matched on whole identifier segments; negated forms (`optional`, `anonymous`, `skip`, `bypass`, `public`) never count.
      - One row per handler and recipient origin; `line_start` is the recipient read nearest the send, `line_end` the send; the code window ends at the send. The description carries only fixed text and those two line numbers.
- **Severity**: high (CWE-400, CWE-404, CWE-476), medium (CWE-770, CWE-799 rate_limit / express_rate_limit); `anonymous_message_send` is high, or medium when a quota identifier is in scope (a quota lowers severity, it never silences).
- **anonymous_message_send does not fire on**: an authenticated, signature-verified or shared-secret-verified (webhook, event trigger) handler; a recipient from a parameter typed as a query result (a stored row); a server-verified CAPTCHA / proof-of-work gate; a constant, configured, or principal-derived recipient; a helper whose recipient is only a parameter (templates); CLI `args`; a send in a comment; a declaration of a send-named function; a generic `to` that is not an address (a chat channel, a queue); test, generated and prose files.
- **anonymous_message_send known limits**: auth enforced in another file (middleware or security config) is not seen — triage the row; a shared secret compared inline (`header !== process.env.HOOK_SECRET`, a constant-time compare) or verified by a wrapper / decorator is not read as a gate; helper arguments are matched by position (a spread or keyword call can mis-assign one); layered code where a service in another file sends to a parameter is not seen; a recipient set on a message object (`msg.setTo(x); send(msg)`), paren-less calls (`Mailer.deliver_later`), and queued sends are not seen. Lines over 2000 characters are not read, and at most 200 send calls are evaluated per file (truncation is logged).

## info_exposure_check

- **Function**: `check_information_exposure(source_path: str) -> dict`
- **Purpose**: Detects information disclosure through error messages, logs, cleartext storage
- **CWE Coverage**:
  - **CWE-209** Error Message Disclosure: Stack traces in responses
  - **CWE-532** Sensitive Data in Logs: Passwords/tokens in log output
  - **CWE-312** Cleartext Storage: Sensitive values in plaintext
  - **CWE-200** Sensitive Info Exposure: Internal details in responses
- **Severity**: critical (CWE-532, CWE-312), high (CWE-209, CWE-200)

## access_control_check

- **Function**: `check_access_control(source_path: str) -> dict`
- **Purpose**: Detects authorization and access control vulnerabilities
- **Files**: generated, test and prose files are skipped; no rule reads a filename or a suffix.
- **CWE Coverage**:
  - **CWE-862** Missing Authorization (`cwe.access_control.missing_authz`): a route registration (Flask/FastAPI decorator, Go router, Spring mapping, Express `app.<verb>(`) with no auth middleware or decorator in its OWN statement or decorator stack, and not covered by an Express `app.use('<prefix>', <authz>)` mount (segment-aware). One row per route; 3 or more in one file become ONE rollup row (`is_rollup`, `instance_count`, the distinct paths). `high` when the file has route/handler context, else `medium`.
  - **CWE-425** Forced Browsing (`cwe.access_control.forced_browsing`): an unprotected route (same decision as 862) whose path has an administrative segment (`admin*`, `administrator`, `sysadmin`, `superadmin`, `actuator`, `management`, `metrics`). `high`. Emitted beside the 862 row; the platform's line-stack collapse keeps 425 (ChildOf 862).
  - **CWE-863** Incorrect Authorization (`cwe.access_control.role_string_cmp`): a role compared with a privileged string literal (`role === 'admin'`, `user.role != "root"`, `roles.includes('admin')`). `high`.
  - **CWE-639** IDOR (`cwe.access_control.idor`): a user-supplied `*id` request value with no ownership check in the file. `high`. **CWE-566** (`cwe.access_control.sql_pk_bypass`) REPLACES the 639 row on a line where that value is the primary key of an ORM lookup (`where: { id: ... }`, `objects.get(pk=...)`, `findByPk(...)`, `find(params[:id])`, or a one-hop `const id = ...` reaching `where: { id }`) with no owner/tenant column scoping it.
  - **CWE-269** Improper Privilege (`cwe.access_control.improper_privilege`): `chmod 777`, `os.chmod(..., 0o777)`, `--privileged` / run as root, `setuid(0)`. `critical`.
  - **CWE-807** Reliance on Untrusted Inputs in a Security Decision / **CWE-290** Authentication Bypass by Spoofing (feature 0097): an auth guard whose APPLICATION (runs / skipped / satisfied) is decided by a client-controlled request attribute. Framework-neutral; see below.
- **Severity**: critical (CWE-269); high (CWE-863, CWE-639, CWE-566, CWE-425, CWE-807, CWE-290); high or medium (CWE-862)

### Guard decided by a client-controlled request attribute (CWE-807 / CWE-290)

Every row is `high` and blocks the offline pre-commit gate, so every row needs three co-occurring signals: (1) a client-attribute read or a scoped exclusion key, (2) a skip / grant / exclusion confined to that branch or declaration, (3) guard semantics confined to the enclosing scope, the module outside the matcher, or the declaration itself. Structural tokens are matched on code with strings and comments blanked (multi-line constructs too: a line wholly inside a triple-quoted string or docstring, a template literal or a `/* */` block, with or without leading `*`, is not code); attribute names and literals are read from the raw line. A file is examined only when a request accessor or an exclusion keyword appears in it. Rows are unique per (line, check_id).

| check_id | CWE | Arm |
|---|---|---|
| `cwe.access_control.guard_skip_by_request_attr` | CWE-807 | imperative skip / grant |
| `cwe.access_control.spoofable_identity_guard` | CWE-290 | imperative, client-asserted identity compared |
| `cwe.access_control.guard_excluded_by_request_attr` | CWE-807 | declarative exclusion (route matcher and framework hooks) |

- **Client attribute reads** (receiver-anchored, case-sensitive): headers (`req.headers[...]` / `.get(` and their optional-chaining forms `?.[` / `?.get(`, `req.get(` / `req.header(`, `<x>req.getHeader(` / `<x>Request.getHeader(` (any receiver ending in `req` / `Req` / `request` / `Request`), Go `r.Header.Get(` / `r.Header[...]`, gin `c.GetHeader(` / `c.Request().Header.Get(`, Fiber `c.Get(...)` only when directly compared with `==` / `!=` (gin's two-valued `c.Get` reads the server-side context store), Hono `c.req.header(`, Rack `request.get_header('HTTP_*')`, `$_SERVER['HTTP_*']`, Django `request.META['HTTP_*']`, Laravel `$request->header(` / `hasHeader(`, Symfony `$request->headers->get(`, ASP.NET `Request.Headers`, Koa `ctx.request.headers`); query (`req.query` and `req.query?.x`, `request.args` / `GET` / `query_params` / `values`, `searchParams.get(`, `URL.Query().Get(`, `c.Query(` / `c.QueryParam(` / `c.DefaultQuery(`, Hono `c.req.query(`, `<x>req.getParameter(`, `$_GET` / `$_REQUEST`, `$request->query(` / `input(` / `boolean(`, `r.FormValue(`, `params[...]`, `Request.Query` / `Form`); body (`req.body` and `req.body?.x`, `request.form` / `json` / `POST` / `data`, `$_POST`); cookies (`req.cookies` and `req.cookies?.x`, `request.COOKIES`, `cookies().get(`, Koa `ctx.cookies.get(`, Rails `cookies[:x]`, `r.Cookie(`, `$_COOKIE`, `$request->cookie(`, `Request.Cookies`); a client-asserted identity read as a member (Go `r.UserAgent()` / `r.Referer()` / `r.Host`, Express `req.hostname` / `req.host`, Flask `request.host` / `request.user_agent` / `request.referrer`); Python membership that names the attribute first (`"<name>" in request.headers` / `args` / `GET` / `query_params` / `values` / `form` / `POST` / `json` / `cookies` / `COOKIES`; `"<name>" not in ...` is not a read). The read is on the branch line, or is a one-hop alias assigned within the 5 lines above whose identifier the condition uses. Server-observed values (`req.ip`, `remote_addr`, `RemoteAddr`, `REMOTE_ADDR`, path, method, `req.user`, session) are never reads.
- **Imperative arm**: a branch (`if` / `elif` / `else if` / `elsif` / `unless`; not a Ruby `if:` option) on such a read, whose OWN body (the line itself for an inline branch, else up to 3 scoped lines, brace or indent) does one of: return `next()` / `_next(` / `call_next` / `$next` / `NextResponse.next()` / `get_response` / `view(...)` / `<fn>(*args`; return `c.Next()` / `ctx.Next()` (Fiber); call `next.ServeHTTP` / `chain.doFilter` / `c.Next()` / `next()` / `await next()` / ASP.NET `await _next(context)` / `_next.Invoke(context)` / `app.Use` lambda `await next(context)` and then `return`; call any of those as the branch's only effect when the branch is closed by `} else` (the else carries the guard); a bare `return` (or `return None` / `return nil`) within 15 lines below a `@x.before_request` or fastify `onRequest` / `preHandler` / `preValidation` hook; `context.Succeed(`, or `return true` within 15 lines below `canActivate` / `has_permission` / `authorize*(` (both intrinsic grants); `return true` within 15 lines below a Spring `preHandle(` (it continues the chain, so it is a skip that needs guard evidence); return a principal built in the branch (`return User(...)`, `return new Principal(...)`, `AuthUser(`, `ClaimsPrincipal(`, `UserEntity(`: a case-sensitive constructor whose name ENDS in `User` / `Principal` / `Identity` / `Claims`, optionally `Entity` / `Model` / `Record`; `UserPreview(`, `UserSummary(`, `UserDto(` are data) from a principal PROVIDER within 15 lines above, i.e. a function whose name ends in `user` / `principal` / `identity` / `claims` / `auth` / `authenticate` (`get_current_user`, `getUser`, `resolvePrincipal`) or a Passport `validate(` (a route handler returning a user object is not one); a grant that needs guard evidence; an `Anonymous*` / `Guest*` principal asserts no identity and grants nothing); or set an `authorized` / `authenticated` / `authed` / `allowed` / `logged_in` / `admin` flag (optionally `is_`-prefixed) to true, bare or on `req.` / `request.` / `g.` / `self.` / `this.` / `ctx.` / `request.state.` / `ctx.state.` / `res.locals.` / `$this->`. For every non-intrinsic outcome, guard evidence must follow in the ENCLOSING scope only (to its closing brace or its dedent, at most 30 lines). Guard evidence is a DENY: a 401 / 403 passed to `status(` / `status:` / `status =` / `statusCode =` / `status_code=` / `Status(` / `StatusCode` / `sendStatus(` / `abort(` / `http_response_code(` / `AbortWithStatus*(` / `writeHead(` / `WriteHeader(` / `code(` / `SendStatus(` / `throw(` / `createError(` / `HTTPException(` / `sendError(`, a trailing `, 401` / `, 403` argument or tuple element (`c.text("..", 401)`, Flask `return body, 401`), `Status{Unauthorized,Forbidden}` on any receiver (`http.`, `fiber.`), Echo `ErrUnauthorized` / `ErrForbidden`, `HTTP_401_*` / `HTTP_403_*`, `HttpStatus.UNAUTHORIZED`, `SC_UNAUTHORIZED`, ASP.NET `StatusCodes.Status401*` / `Status403*`, `HttpResponseForbidden`, `PermissionDenied(` / `Unauthorized*(` / `Forbidden*(` / `AccessDenied*(` / `NotAuthenticated(`, `jwt.verify(` / `jwtVerify(` / `verifySession(`, `authenticate<Suffix>(` / `passport.authenticate(`, `login_required`, `withAuth(`, `require_user*(` / `requireAuth*(` / `ensureAuth*(`, a raw `HTTP/1.x 401|403` status line, a redirect or rewrite whose first string literal names a login / sign-in / auth target (the keyword inside that one literal, on one line: an HTTPS or canonical-host redirect is not one, and neither is a later line's `auth` identifier), or this skill's authz middleware vocabulary. A READ of the caller's identity (`current_user`, `currentUser`, `is_authenticated`, `isAuthenticated`, `getSession(`, `getServerSession(`, `getToken(`, `auth()`, bare `authenticate(`) is NOT evidence by itself (locale, metrics, tracing and feature-flag middleware read it too); it counts only as a NEGATED branch condition (`!` / `not` before it, or `== null / undefined / nil / false`, `is None` after it) whose own body denies, redirects, rewrites or returns false. A 403 in the NEXT function does not qualify. A gate on an attribute NAMED as a feature or challenge gate (`beta`, `opt_in`, `consent`, `captcha`, `cf_clearance`, `clearance`, `challenge`, `experiment`, `variant`, `ab_test`, `age_gate`, `waitlist`, `early_access`) or as a routing selection (`tenant`, `api_version` / `client_version` / `version`), as a whole segment of a name that carries no bypass word (`skip`, `bypass`, `auth`, `admin`, `internal`, `debug`, `override`, `trust`, `privileg*`, `super`, `root`, `sudo`, `backdoor`, `impersonat*`, `staff`: `cookie_consent` is a gate, `x-admin-clearance`, `skip_auth_variant` and `beta_admin_bypass` are not; any kind), and a compared Referer (CSRF), need an INDEPENDENT guard: a named guard call, a 401 or a login redirect, or a deny under a condition of its own; its own fall-through 403 does not count. Evidence is computed once per file (per line), so cost is linear in file size. Anchor: the branch line; one row per branch.
- **CWE-290 instead of CWE-807**: the attribute is a client-asserted source identity (`x-forwarded-for`, `forwarded`, `x-real-ip`, `client-ip`, `true-client-ip`, `cf-connecting-ip`, `cluster-client-ip`, `originating-ip`, `x-forwarded-host`, `host` / `hostname`, `referer` / `referrer` (a CSRF signal too: see the independent-guard rule above), `user-agent` / `user_agent` / `UserAgent`, or their `HTTP_*` forms) AND the condition compares it or tests membership (`===` / `==` / `!=`, `in`, `includes(` / `has(` / `contains(` / `in_array(` / `indexOf(` / `test(` / `match(` / `equals*(`, a prefix or suffix test `startsWith(` / `startswith(` / `endsWith(` / `endswith(` / Go `strings.HasPrefix(` / `HasSuffix(` / `EqualFold(`, or a lookup keyed by the read such as `trusted[r.Header.Get("X-Real-IP")]`). The 290 row replaces the 807 row at that site; a bare presence test of an identity header emits nothing.
- **Route-matcher arm** (declarative): inside the bracket-balanced value of a `matcher:` key (a quoted `"matcher":` key too, or a `const matcher = [...]` that the same file binds into its config by shorthand, `config = { matcher }`), the first `has: [` / `missing: [` condition whose own array carries `type: 'header' | 'cookie' | 'query'`, in a module whose code OUTSIDE the matcher carries guard evidence (as above, so a next-auth `withAuth(...)` default export, an `export { default } from "next-auth/middleware"` re-export, an auth module's guard re-exported as the middleware (Auth.js `export { auth as middleware } from "@/auth"`; `default` / `middleware` / `proxy` from a module path naming `auth`), or a rewrite to the login page qualifies). One row per matcher, anchored on that condition line (not on the first `has:` in the file). How the config object is exported is irrelevant. A Next.js middleware `config.matcher` is one instance: a request that carries (or omits) the attribute never reaches the guard.
- **Framework exclusion hooks** (declarative): Rails `skip_before_action` / `skip_around_action`, and the guard's own `before_action` / `around_action` / `prepend_before_action` (`*_filter` too), naming an auth symbol (not a CSRF filter: `:verify_authenticity_token`, `*forgery*`, `*csrf*` are excluded) with `if:` / `unless:` reading `request.headers` / `request.get_header` / `params` / `cookies` (`params[:controller]` / `params[:action]` are set by the router, not the client, and do not count; a declaration wrapped onto up to 2 continuation lines after a trailing `,` is one declaration; a complementary PAIR, i.e. another auth filter that runs exactly when this one does not (the same condition text with the opposite polarity, e.g. `before_action :authenticate_user_from_token!, if: -> { params[:x].present? }` + `before_action :authenticate_user!, unless: -> { params[:x].present? }`), chooses between two authentication methods and is silent); Spring `RequestHeaderRequestMatcher(...)` that IS the argument of the permit rule on the same chain (within 2 lines above / 2 below): `requestMatchers(<m>).permitAll()` (also `antMatchers` / `mvcMatchers`), `ignoring().requestMatchers(<m>)`, or the Kotlin DSL `authorize(<m>, permitAll)`; a matcher that feeds an entry point (`defaultAuthenticationEntryPointFor`), a CSRF exemption (`ignoringRequestMatchers`) or a path `permitAll()` nearby does not count, nor does a matcher held in a variable or a lambda `RequestMatcher` (not seen); `.unless({ custom: ... })` whose function reads the request within its first 4 lines, with `expressjwt` / `jwt` / `passport.authenticate` / `requireAuth*` within the 3 lines above; Echo `Skipper:`, Fiber `Next:` and gofiber jwtware `Filter:` funcs reading a header, query or cookie within their first 4 lines, when the config literal that OWNS the hook (the nearest unbalanced `(` / `{` opener, at most 8 lines up) names `echojwt` / `jwtware` / `keyauth` / `basicauth` / `KeyAuth*` / `BasicAuth*` / `JWT*`; a Skipper in a sibling Logger / Gzip config is not the auth guard's. The attribute vetoes (1)-(3), the comparand veto (5) and a verifier (6, e.g. `secure_compare`) in the hook below apply to every declaration. One row per declaration.
- **Vetoes** (any one silences an imperative site; (1)-(3) and (5) also a declarative one): (1) credential names (`authorization`, `cookie`, `api-key`, `auth_token` / `api_token` / `access_token` / `bearer_token` with an optional `x-` prefix and `-` / `_`, `token`, `jwt`, `signature` / `x-signature` / `x-hub-signature-256`, `session*`, `sid`, `csrf` / `xsrf` with an optional `x-` / `_` prefix and `token` suffix, `x-csrftoken`, `csrf_token`, `_csrf`, `csrfmiddlewaretoken`, `authenticity_token`) and neutral names (`accept*`, `content-*`, request / trace ids, `cache-control`, `x-requested-with`, `origin` (comparing it is the recommended CSRF defence, so it is not a spoofed identity), the CORS preflight headers `access-control-request-method` / `access-control-request-headers`, `lang`, `locale`, `theme`, `format`, `fmt`, `page`, `per_page`, `page_size`, `limit`, `offset`, `cursor`, `sort`, `order`, `q`, `search`, `callback`); (2) gateway-injected identity headers (`x-forwarded-user` / `email` / `groups`, `x-goog-*`, `x-ms-client-principal*`, `x-amzn-oidc-*`, `x-forwarded-client-cert`, `cf-access-*`, `remote-user`); (3) a privilege cookie (`isAdmin`, `role`, `user_id`, ...), owned by web_security CWE-784 / CWE-565; (4) a privileged role string compared on the line, owned by CWE-863; (5) the equality COMPARAND, i.e. the value on the other side of `===` / `==` / `!=` / `.equals(` from the read (a default argument such as `.get("X", "")` skipped; never elsewhere in the condition, so a feature-flag conjunct such as `&& config.allowDebug` does not silence the row), is a value the client cannot know: anything other than a literal that is the whole comparand (a trailing `/* comment */` allowed), another request read (`=== req.cookies.x`, `== request.args.get('role')`: the client sets both sides), or an identifier (also an enum member read through `.value` / `.name`), bare or qualified by a TYPE (a capitalised `Mode.` / `Flags.` / `Constants.Mode.`, or PHP `self::` / `static::`), bound in the same file only to non-placeholder literals. Literal bindings include TS `as const` / `as <Type>` / `satisfies T`, PHP `define('NAME', <literal>)`, each declarator of `const A = 'x', B = 'y'`, and the `key: <literal>` members of a same-line object literal (`{ debug: 'on' }`, `Object.freeze({ BYPASS: 'yes' })`), resolved only qualified by that object (`MODES.debug`, never a bare `debug`). Server-held: env, config and settings values; anything read through a lower-case qualifier (`settings.x`, `cfg.x`, `config.x`, `this.x`, `self.x`: an instance, loaded at runtime, even when a same-file field DEFAULT such as pydantic `internal_token: str = "change-me"` exists); calls; imported names (`from x import NAME`, even with a literal fallback); a binding whose innermost open bracket is `(` (a parameter default on a wrapped parameter list, a keyword argument; a callback BODY or a Go `const (` group is not one); a name first set to a placeholder (`''`, `None`, `null`) and loaded later; and a name whose literal is only a DEFAULT, assigned a non-literal ANYWHERE in the file (a conditional or one-line override `if (prod) secret = process.env.S`, a callback `.then((s) => { secret = s.k })`, a Go `init()`, a second statement on a line, a compound `+=`). The comparand of a static two-argument equals (`Objects.equals(<read>, X)`, `StringUtils.equals`) is `X`, not the receiver type. For a one-hop alias, the alias line's own comparison counts too (`const ok = <read> === process.env.T; if (ok)`). Equality with such a value is a shared secret, i.e. authentication. NOT applied to identity attributes, since a forged X-Forwarded-For matches a configured allowlist too; (6) a verifier in the condition or in the branch's own body (`hmac`, `compare_digest`, `secure_compare`, `timingSafeEqual`, `constructEvent`, `verify*(`, `jwtVerify`, `validate*Signature`, `checkSignature`, `isValid*Request|Signature|Webhook|Hmac(`, any `*signature*(` call, `MessageDigest.isEqual`, `ConstantTimeCompare`): an authenticated webhook path; or a verifying call (a verb `verify` / `authenticate` / `check` / `validate` / `is_valid` and a credential noun `jwt` / `token` / `signature` / `sig` / `hmac` / `auth` / `credentials` / `session` in its name, e.g. `check_service_jwt(`; a CSRF validator such as `validateCsrfToken(` is not one: it proves the request came from the app's page, not who sent it) conjoined with the read by `&&` / `and`, not negated (`!` / `not`, also before `await` and with any whitespace) and not in a disjunction; (7) a negated read (`!`, `not`, `empty(`, `!isset(` before it, or `== null / undefined / None / nil / ''` after it; Go `!= ""` is presence and still fires); (8) a `$_SERVER` / `META` name that is not `HTTP_*`.
- **Does not fire on**: a commented-out matcher or condition, or an anti-pattern shown inside a docstring, block comment or template literal; a `has` / `missing` key outside a matcher; a path-only matcher; a matcher condition on a middleware that enforces no auth (CSP nonce, i18n, analytics: excluding requests from it bypasses nothing); path or method exemptions (a CORS preflight exemption that also tests `Access-Control-Request-Method` included); middleware whose only later use of the caller's identity is a read (analytics, locale, logging, metrics, tracing, A/B, feature flags); server-observed addresses (a misconfigured `trust proxy` stays configuration_check CWE-348); a rate limiter keyed on a client IP header (resource_check `spoofable_rate_limit_key`, its own CWE-807 row); a branch with no skip or grant outcome (logging, tracing, locale); a header compared with a shared secret held by the server; a CSRF double-submit check; a Referer (CSRF) check answering 403; a beta / consent / captcha-clearance gate, or a tenant / API-version selection, answering 403; a route handler returning a DTO or summary early (`return new UserPreview(body)`); a secret whose same-file literal is only a default that is overridden; an HTTPS or canonical-host redirect; a Rails pair of auth filters that chooses between two authentication methods; an anonymous principal; anything vetoed above.
- **Known limits**: multi-line conditions (a Prettier-wrapped `if (\n a &&\n b\n)`), a matcher re-exported from another module (`export { config } from './mw/config'`), ASP.NET `context.Request.Host` / `Request.UserAgent` and Django `request.get_host()`, reads hidden behind helpers (`isInternal(req)`), FastAPI `Header()` / `Query()` parameters, destructured reads, principal adoption without a branch, guards split across files, and a guard NESTED inside the negated branch (`if (h !== '1') { if (!user) deny }`) are not seen. A guard implemented only by an unnamed helper (`if (!ok(req)) return deny()`) gives no guard evidence. A disjunction whose verifying call sits in a nested conjunct (`header || (user && verifySession())`) is silent. Veto 5 treats as server-held, and so is silent on: a constant imported from another module, a method call on a constant (`ON.toLowerCase()`), a class constant read through `self.` (`self.BYPASS`), and `!==` against a server value; same-file name resolution can collide across scopes (a name bound to anything other than a literal anywhere in the file is server-held). A hardcoded secret compared as a literal still fires CWE-807: the value is client-knowable once leaked, and secret_scan (CWE-798) owns the secret itself. A real bypass attribute whose name uses the gate vocabulary and none of the bypass words (`x-beta-tester`) answering only 403 is silent unless a named guard, a 401 or a login redirect follows. A principal returned under another name (`return Account(...)`), or from a provider not named as one, is not a grant. A ternary skip (`return <read> === '1' ? next() : deny()`) and a Spring lambda request matcher (`requestMatchers(request -> "true".equals(request.getHeader("X"))).permitAll()`) are not seen. A literal reached through a lower-case object (`const opts = { token: 'x' }` ... `opts.token`), or an object literal spanning several lines, is treated as server-held.
- **Recommendation emitted**: apply the guard unconditionally; exempt only by server-side route metadata or an authenticated caller (HMAC, signed token, mTLS); strip internal marker headers such as `x-middleware-subrequest` at the edge; derive the client IP from the socket or a bounded trust-proxy hop count; match guarded routes by path only.
- **Not this rule**: CVE-2025-29927 (Next.js honouring a client-sent `x-middleware-subrequest` header and skipping middleware) is a framework bug, fixed by upgrading Next.js; no rule here detects a vulnerable Next.js version. Application code that itself trusts such an internal marker header is an ordinary imperative-arm row.

## error_handling_check

- **Function**: `check_error_handling(source_path: str) -> dict`
- **Purpose**: Detects error handling weaknesses
- **CWE Coverage**:
  - **CWE-252** Unchecked Return Value: Go `_, _ = func()` patterns
  - **CWE-755** Improper Exception Handling: Bare `except:`, `catch(...)`
  - **CWE-390** Error Without Action: Empty catch/except blocks
  - **CWE-754** Unchecked I/O: I/O without error handling
- **Severity**: high (CWE-252, CWE-755, CWE-390), medium (CWE-754)

## concurrency_check

- **Function**: `check_concurrency(source_path: str) -> dict`
- **Purpose**: Detects concurrency vulnerabilities
- **CWE Coverage**:
  - **CWE-367** TOCTOU: File check followed by file use
  - **CWE-662** Improper Synchronization: Threading without locks
  - **CWE-833** Deadlock: Nested lock acquisition
- **Severity**: high (CWE-367, CWE-662, CWE-833)

## web_security_check

- **Function**: `check_web_security(source_path: str) -> dict`
- **Purpose**: Detects web-specific security vulnerabilities including redirects, cookies, and session handling
- **CWE Coverage**:
  - **CWE-601** Open Redirect: User-controlled redirect targets without URL validation
  - **CWE-1004** Cookie Without HttpOnly: Cookies set without HttpOnly flag
  - **CWE-384** Session Fixation: Session populated from user input without regeneration
  - **CWE-614** Cookie Without Secure: Cookies missing Secure flag for HTTPS
  - **CWE-113** CRLF Injection: User input in HTTP headers without CR/LF stripping
- **Severity**: high (CWE-601, CWE-384, CWE-113), medium (CWE-1004, CWE-614)
- **Detection**: Context-aware scanning with safe-pattern exclusions (URL validation, HttpOnly/Secure flags, session regeneration)

## configuration_check

- **Function**: `check_configuration(source_path: str) -> dict`
- **Purpose**: Detects configuration and deployment security issues
- **CWE Coverage**:
  - **CWE-1188** Insecure Default Initialization: DEBUG=True, CORS allow all, verify=False
  - **CWE-668** Service Bound to All Interfaces: Binding 0.0.0.0 without restriction
  - **CWE-326** Weak TLS/SSL Protocol: TLS 1.0, SSLv3, weak protocol versions
  - **CWE-295** Certificate Verification Disabled: InsecureSkipVerify, verify=False
  - **CWE-319** Weak HSTS Configuration: Short max-age values
  - **CWE-732** Incorrect Permissions: chmod 777, umask(0), world-writable files
  - **CWE-668** Resource Exposure: Internal ports exposed publicly (3306, 5432, 6379)
  - **CWE-1295** Debug in Production: Debug mode enabled outside dev/test context
- **Severity**: high (CWE-732, CWE-668, CWE-1295), medium (CWE-1188, CWE-326, CWE-295, CWE-319)
- **Detection**: Scans code and config files (.py, .go, .yml, .toml, .ini, .env, etc.); excludes test/dev files

## dependency_check

- **Function**: `check_dependency_security(source_path: str) -> dict`
- **Purpose**: Detects supply chain and dependency security issues
- **CWE Coverage**:
  - **CWE-1104** Unmaintained Components: Unpinned dependency versions in requirements.txt
  - **CWE-829** Untrusted Source: Scripts loaded over HTTP, pipe-to-shell installs
  - **CWE-494** Download Without Integrity: Code downloaded without checksum verification
  - **CWE-506** Embedded Malicious Code: Base64-decode-then-exec patterns, obfuscated execution
- **Severity**: critical (CWE-506), high (CWE-829, CWE-494), medium (CWE-1104)
- **Detection**: Scans dependency manifests (requirements.txt, package.json, go.mod) and code files; SRI/checksum context exclusions

## data_handling_check

- **Function**: `check_data_handling(source_path: str) -> dict`
- **Purpose**: Detects data handling and type safety vulnerabilities
- **CWE Coverage**:
  - **CWE-134** Format String: User input as format string argument in printf/sprintf/logging
  - **CWE-681** Incorrect Numeric Conversion: Narrowing casts without overflow checks
  - **CWE-704** Unsafe Type Cast: `reinterpret_cast`, `unsafe.Pointer`, TypeScript `as any`
  - **CWE-838** Inappropriate Encoding: ASCII/Latin-1 with errors='ignore', encoding mismatches
  - **CWE-1321** Prototype Pollution: Object.assign/merge/spread from user input without validation
- **Severity**: high (CWE-134, CWE-704, CWE-1321), medium (CWE-681, CWE-838)
- **Detection**: Pattern matching with safe-alternative exclusions (schema validators, Object.create(null), UTF-8)

## memory_safety_check

- **Function**: `check_memory_safety(source_path: str) -> dict`
- **Purpose**: Detects memory lifecycle and initialization bugs in C/C++/Go/Rust
- **CWE Coverage**:
  - **CWE-401** Memory Leak: malloc/calloc/new without matching free/delete in file
  - **CWE-415** Double Free: Same pointer freed twice within 10 lines
  - **CWE-457** Uninitialized Variable: Variable declared without initialization before use
  - **CWE-824** Uninitialized Pointer: Pointer dereferenced before initialization
  - **CWE-562** Return Stack Address: Returning address of local variable
  - **CWE-467** sizeof on Pointer: `sizeof(ptr)` instead of `sizeof(*ptr)`
- **Severity**: critical (CWE-415, CWE-824, CWE-562), high (CWE-401), medium (CWE-457, CWE-467)
- **Detection**: Scans C/C++/Go/Rust files only; window-based analysis for use-after-alloc and double-free patterns

## path_equivalence_check

- **Function**: `check_path_equivalence(source_path: str) -> dict`
- **Family**: Path-equivalence weaknesses — children of CWE-41 (Improper Resolution of Path Equivalence). These are string-equivalence tricks on filenames that bypass allowlists, path comparisons, or access controls.
- **CWE Coverage**:
  - **CWE-42** Trailing Dot ('filedir.'): `foo.txt.`
  - **CWE-43** Multiple Trailing Dots ('filedir...'): `foo.txt....`
  - **CWE-46** Trailing Whitespace ('filedir '): `foo.txt ` (space/tab at end)
  - **CWE-48** Internal Whitespace ('file(SPACE)name'): `foo bar.txt`
  - **CWE-49** Trailing Slash ('filedir/'): `foo.txt/`
  - **CWE-50** Multiple Leading Slashes ('//absolute/path'): `//etc/passwd`
  - **CWE-51** Multiple Internal Slashes ('/absolute//path'): `/etc//passwd`
  - **CWE-52** Multiple Trailing Slashes ('filedir//'): `/etc/passwd//`
  - **CWE-54** Trailing Backslash ('filedir\\'): `foo\\`
  - **CWE-55** Path Equivalence Using Single Dot ('/./'): `/./foo`
  - **CWE-56** Path Equivalence: 'filedir*' (Wildcard): `foo*.txt`
  - **CWE-57** Path Equivalence: 'fakedir/../realdir/filename': `fake/../real/f`
- **Detection Approach** — two-stage filtering to suppress false positives:
  1. **Path-call gate**: The line must invoke a recognized filesystem API (Python `open`/`os.path.*`/`pathlib.Path`, Go `ioutil.ReadFile`, Java `Files.read`/`Paths.get`, JavaScript `fs.readFile`, C `fopen`/`unlink`/`stat`, etc.). Lines without such a call are skipped — this filters out log messages, regex patterns, version strings, URLs inside `requests.get`, etc.
  2. **Path-shape filter**: The quoted literal content must contain at least one path signal (`/`, `\`, `../`, an extension tail like `.py`/`.json`, or a trailing dot). Plain identifiers like `"Hello world"` inside a path call are excluded.
  3. **Variant regexes**: Each of the 12 variants is a compiled pattern with absolute anchors `\A` / `\Z` operating on the literal content only. One variant per literal (first match wins, ordered by specificity).
- **Severity** (calibrated to false-positive risk):
  - **high**: CWE-57 (directory-traversal equivalence — high-signal, classical `../` bypass)
  - **medium**: CWE-43, CWE-54, CWE-52, CWE-50, CWE-51, CWE-55 (specific path shapes, low FP)
  - **low**: CWE-42, CWE-46, CWE-48, CWE-49, CWE-56 (noisier variants — trailing dot, whitespace, wildcard)
- **FP Risk Note**: Wildcards (CWE-56) can still fire on glob-style path literals passed to `open(glob_result)` — this is by-design (catalog variant) but requires manual review. Internal-whitespace (CWE-48) assumes filenames with embedded spaces are unusual; this may produce FPs on legitimate filenames with spaces.
- **Language-agnostic**: Scans all source extensions; skips test and generated files.

## divide_by_zero_check

- **Function**: `check_divide_by_zero(source_path: str) -> dict`
- **CWE Coverage**: **CWE-369** Divide By Zero.
- **Detection**: Binary `/` or `%` operator whose RHS is a non-literal identifier (`\b(\w+)\s*([/%])\s*([A-Za-z_]\w*)\b`).
- **Safe-context** (5-line preceding window): `(?:!=|==|>|<)\s*0`, `is_zero`, `isZero`, `.is_zero(`, `assert ... (!=|==) 0`.
- **Language-gate**: `.c .h .cpp .cc .cxx .hpp .go .rs` (undefined-behavior languages; Python / JS / Java raise a well-defined exception instead).
- **Severity**: medium.

## dangerous_function_check

- **Function**: `check_dangerous_function(source_path: str) -> dict`
- **CWE Coverage**: **CWE-676** Use of Potentially Dangerous Function, **CWE-242** Use of Inherently Dangerous Function. Both are **corpus-VERIFIED** (feature 0060): recall 1.0 / fp-rate 0.0 over the labeled `dangerous_functions` corpus — this measures precision/recall on those fixtures, **not** exhaustive sink coverage.
- **Scope (feature 0060)**: memory-unsafe *library* functions in systems languages only. **Command/code execution (`eval`/`exec`/`os.system`/`os.popen`/`Runtime.exec`) is NOT here — it is owned by `injection_check`** (CWE-78 / CWE-94), which applies a receiver-boundary that excludes benign method calls like `RegExp.exec()` and ioredis `pipeline.exec()`. This split removed the historical CWE-676↔CWE-78 double-report and a class of `.exec()` false positives.
- **Detection (language-scoped via `detect_language`)**:
  - **C / C++ / Objective-C** (`.c .h .cpp .cc .cxx .hpp .m .mm`): `gets` → CWE-242 (critical); `strcpy strcat sprintf vsprintf scanf sscanf strdup strndup vfprintf vprintf tmpnam tempnam mktemp alloca getwd` → CWE-676 (high).
  - **Go** (`.go`): `unsafe.Pointer|Sizeof|Alignof|Offsetof` → CWE-676 (high).
  - **Rust** (`.rs`): `transmute`, `.get_unchecked(_mut)`, `ptr::read|write*` → CWE-676 (high).
- **Boundary rules**: bare C sinks carry a receiver-reject lookbehind (`obj.strcpy(` is not matched); a sink token that is the function being *defined* (`fn transmute(...)`) is not matched; pure comment lines are skipped; C string-handling is suppressed by a bounded alternative (`strncpy`/`strlcpy`/`snprintf`/`strlcat`) in the prior 5-line window.
- **Language-gate**: only C/C++/Objective-C, Go, Rust files are scanned for these sinks; other languages produce no `dangerous_function` findings (their dangerous ops are execution sinks, owned by `injection`).
- **Severity**: `gets` critical (242); all other sinks high (676).
- **Kill switch**: `VULTURE_CWE_DISABLE_DANGEROUS_FN=true` disables the skill for one release (rollback safety).

## insufficient_logging_check

- **Function**: `check_insufficient_logging(source_path: str) -> dict`
- **CWE Coverage**: **CWE-778** Insufficient Logging.
- **Detection**: Python `except:` or Java/JS/C#/Go `catch(...)` block whose first 5 non-blank body lines contain no logging call.
- **Logging regex** (body must match one): `log.`, `logger.`, `logging.`, `slf4j`, `console.error`, `console.warn`, `syslog`, `LOG_*`, `fmt.Fprintf(os.Stderr`.
- **Language-gate**: `.py .java .js .ts .go .cs .rb .php`.
- **Severity**: medium.

## uncaught_exception_check

- **Function**: `check_uncaught_exception(source_path: str) -> dict`
- **CWE Coverage**: **CWE-248** Uncaught Exception.
- **Detection**:
  * Java method decl with generic `throws Exception`.
  * Python `except Exception` whose first body line is bare `pass` or bare `raise`.
- **Safe-context** (body must NOT match): `raise X(Error|Exception)(...)`, `throw new XException(...)`, `from <var>`, `chain(`, `__cause__`.
- **Language-gate**: `.java .py`.
- **Severity**: medium.

## weak_entropy_check

- **Function**: `check_weak_entropy(source_path: str) -> dict`
- **CWE Coverage**: **CWE-331** Insufficient Entropy, **CWE-332** Insufficient Entropy in PRNG.
- **Detection**: Assignment `name = <rhs>` where `rhs` invokes `random.random`, `Math.random`, `rand()` or `new Random()`, and the assignment target matches `token|key|nonce|secret|session|password|iv|salt`.
- **Safe-context / suppress**:
  * File-scope co-occurrence with `secrets.(token|choice|randbelow)`, `SecureRandom`, `crypto.randomBytes`, or `os.urandom`.
  * Target-variable name matches `test|mock|fake|example|cache|demo`.
- **Language-gate**: all languages.
- **Severity**: high.

## catalog_detector

- **Function**: `check_catalog_generic(source_path: str) -> dict`
- **Purpose**: Catalog-driven generic CWE detection engine that keyword-matches against the enriched CWE v4.19.1 metadata. HONESTY NOTE: this path fires ~0 findings on real code — it is metadata/context (catalog names, consequences, rollup parents), NOT a detection-coverage claim. The deterministic detection surface is the 24 dedicated skills (171 declared CWE-ID categories) plus 7 trusted signatures; N=81 of those are corpus-VERIFIED (see `tests/corpus/VERIFIED_CWES.md`).
- **Mechanism**:
  - Loads all CWEs with static-detectability score >= 0.3 from enriched catalog
  - Builds keyword-to-CWE inverted index for fast file-level matching
  - For each code line, extracts keywords and scores against CWE keyword sets
  - Requires at least 2 keyword matches to reduce false positives
  - Filters by language applicability (e.g., C-only CWEs skip Python files)
  - Context-aware safe exclusions (sanitize, validate, escape, etc.) raise threshold
  - Severity derived from CWE catalog consequences (impact → severity mapping)
  - Skips Pillar/Class abstractions (too generic) and all 221 dedicated-skill CWEs (avoid duplication)
  - Limits to 15 findings per file to avoid noise
- **CWE Coverage**: keyword-scannable catalog entries not covered by dedicated skills (metadata/context — fires ~0 on real code, NOT counted in N), nominally spanning:
  - Uncommon injection variants, race conditions, API misuse
  - Platform-specific weaknesses, deprecated function usage
  - Framework-specific patterns, configuration weaknesses
- **Severity**: Derived from CWE catalog consequence impact data (critical/high/medium/low)
- **Detection**: Keyword-based matching with catalog confidence scoring; findings enriched with catalog metadata (name, likelihood, mitigations)
- **Catalog Confidence**: Each finding carries a `catalog_confidence` score = `static_detectability × keyword_match_score`

## secret_scan

- **Function**: `check_secrets(source_path: str) -> dict`
- **Purpose**: Content-pattern detection of hardcoded secrets across cloud / SaaS, PEM private keys, cryptocurrency wallets, and Polkadot/Substrate keys. Complementary to `auth_check`'s name-pattern detection (`auth_check` covers `name = "value"`-shape; this skill covers the SECRET shape itself).
- **Sub-modules**:
  - `pem_blocks` — `-----BEGIN ... PRIVATE KEY-----` blocks (RSA / EC / DSA / OpenSSH / PKCS8 / encrypted variants). Public certs and public keys explicitly **not** flagged.
  - `cloud_providers` — ~40 provider-specific patterns: AWS (`AKIA*`/`ASIA*`), GitHub (`ghp_*`/`ghs_*`/`gho_*`/`ghu_*`/`ghr_*`), GitLab (`glpat-*`), Stripe (`sk_live_*`/`rk_live_*`/`sk_test_*`/`pk_live_*`), Slack (`xoxb-*`/`xoxp-*`/`xoxa-*`/webhook URLs), Google (`AIza*`/`GOCSPX-*`/`ya29.*`), Twilio (`AC*`/`SK*`), SendGrid, Mailgun, Datadog, Heroku, Discord (bot tokens + webhooks), Telegram, Cloudflare, JWT, npm (`npm_*`), PyPI, Square, DigitalOcean, Linear, Notion, Anthropic (`sk-ant-*`), OpenAI (`sk-*`), Hugging Face (`hf_*`).
  - `crypto_wallets` — BIP-39 mnemonic phrases (12/15/18/21/24-word, with vendored 2048-word English wordlist), BIP-32 extended keys (`xprv*`/`xpub*`/`yprv*`/`zprv*`/`tprv*` + Litecoin variants), Bitcoin WIF (with Base58 checksum verification), Ethereum / EVM hex private keys (with context disambiguation against SHA-256), Solana keypair JSON.
  - `substrate` — Polkadot.js encrypted keystore JSON (3-fact match), Substrate dev-account URIs (`//Alice` etc., path-aware severity: `medium` in production, `info` in tests), `subkey` CLI output, SS58 addresses (Substrate / Polkadot / Kusama).
  - `config_files` — JSON / YAML / `.env` config-file extraction. Applies cloud-provider patterns to extracted values + flags suspicious key names with literal values.
  - `entropy` — Shannon-entropy fallback (off by default, `VULTURE_SECRET_SCAN_ENTROPY=true` to enable). Catches generic high-entropy strings without identifier context.
- **CWE Coverage**: **CWE-798** Use of Hard-coded Credentials, **CWE-321** Use of Hard-coded Cryptographic Key, **CWE-200** Information Exposure (for JWTs and SS58 addresses).
- **File-extension override**: Per-skill extension list adds `.pem`, `.key`, `.crt`, `.cer`, `.pfx`, `.ovpn`, `.kdbx`, `.env`, `.envrc`. Other skills' extension lists unchanged.
- **Severity calibration**: PEM unencrypted private keys → critical; encrypted PEMs / encrypted keystores → high; live cloud-provider keys → critical; test variants (`sk_test_*`) → low; informational shapes (Substrate dev URIs in test paths, public addresses) → info. Test/fixture path detection downgrades severity by one level.
- **Redaction**: Findings never include the raw secret bytes — `code_snippet` shows the first 4-6 chars then `[REDACTED]`. PEM blocks are rendered as `BEGIN…[REDACTED — N lines of key material]…END`.
- **Boundary with `auth_check`**: `auth_check.py` covers the LHS-identifier-name shape (`api_key = "..."`); `secret_scan` covers content patterns. Both can fire on the same line; the orchestrator deduplicates within a single run but cross-skill duplicates are intentional (signals two confidences).
- **Boundary with `info_exposure_check`**: `info_exposure_check.py` covers CWE-312 cleartext-storage with the same name-LHS shape. `secret_scan` covers the broader content-pattern surface. No overlap-suppression; both report.
- **Git-history limitation**: Vulture scans the working tree only. Pair with `gitleaks` or `truffleHog` for git-history scanning of removed-but-present-in-history secrets.

## plaintext_transmission_check

- **Function**: `check_plaintext_transmission(source_path: str) -> dict`
- **Purpose**: Detection of cleartext transmission of sensitive information — credentials on the wire, plaintext schemes for services that have a TLS variant, and code that explicitly disables transport verification.
- **Shapes detected**:
  - **Credentials in a URL userinfo part** — `http://user:pass@host/…`.
  - **Plaintext scheme where a TLS variant exists** — `amqp://`, `ftp://`, `ldap://`, `mongodb://`, `mysql://`, `postgres://`, `redis://`, `smtp://`, `telnet://`. Flagged only when the URL appears in code (string literal or assignment), not in prose or comments.
  - **Transport verification disabled at the call site** — `verify=False` on `requests.*` / `httpx.*`, `rejectUnauthorized: false` on Node HTTPS/TLS, `InsecureSkipVerify: true` on Go `tls.Config`.
- **CWE Coverage**: **CWE-319** Cleartext Transmission of Sensitive Information.
- **Suppression**: test-fixture paths, local-loopback hosts (`127.0.0.1`, `localhost`) and documentation comments do not report — a plaintext scheme against loopback is not a transmission exposure.
- **Dispatch note**: this skill and `secret_scan` were implemented and present in `SKILL_MAP` but absent from `config.ALL_CATEGORIES` (the dispatch list), so neither ran. `tests/unit/test_skill_dispatch_conformance.py` now pins `set(ALL_CATEGORIES) == set(SKILL_MAP)` so the two cannot diverge again.

## workspace_autorun_check

- **Function**: `check_workspace_autorun(source_path: str) -> dict`
- **Purpose**: Detection of workspace/editor/IDE/devcontainer configuration that **executes a command when the project is merely opened**, before anybody runs anything and before the command has been reviewed.
- **Why it is a dedicated skill (feature 0091 D2)**: `.vscode`, `.idea`, `.eclipse` and `.claude` are all in the walker's `SKIP_DIRS`, so a scan of a project ROOT never descended into them and this class was invisible to every skill. The one time it was reported it came from the LLM tier of a scan rooted at `.vscode` itself — and an LLM-tier finding enters the next scan's prior-findings block, which instructs the model to skip known issues. The model complied, the absence was read as repair, and the lineage row closed while the offending line sat in the file byte for byte. A deterministic skill is reproducible on every scan, never enters that suppression block, and closes only when the pattern actually leaves the file.
- **File allowlist**: the skill IMPORTS `WELL_KNOWN_AUTORUN_FILES` from `shared.tools.file_scanner` — the same set the walker uses to lift these paths out of an otherwise-pruned directory. One list, never two; `tests/unit/skills/test_0091_workspace_autorun.py::test_the_two_lists_are_one_list` pins the rules' claims equal to the walker's allowlist so neither half can grow alone. Enumeration goes through `scan_autorun_files()`, which is keyed on the PATH and ignores the extension allowlist, because a `.claude/hooks/` entry routinely carries no extension.
- **Rules**:

  | `check_id` | reads | fires on | CWE |
  |---|---|---|---|
  | `cwe.workspace_autorun.vscode_task` | `.vscode/tasks.json`, `.vscode/launch.json` | a task with `runOn: folderOpen` (at the task or inside `runOptions`) that carries a `command` | **CWE-506** |
  | `cwe.workspace_autorun.vscode_env` | `.vscode/settings.json` | a `terminal.integrated.env.*` value containing `$(` or a backtick — evaluated on every integrated-terminal open | **CWE-506** |
  | `cwe.workspace_autorun.idea_run_config` | `.idea/runConfigurations/*.xml`, `.idea/workspace.xml` | a `<command>` element, or a `SCRIPT_TEXT` / `INTERPRETER_PATH` option | **CWE-506** |
  | `cwe.workspace_autorun.devcontainer_hook` | `.devcontainer/devcontainer.json`, `.devcontainer/*.sh` | an `initializeCommand` / `onCreateCommand` / `updateContentCommand` / `postCreateCommand` / `postStartCommand` / `postAttachCommand`; in a script, remote content piped into an interpreter | **CWE-829** |
  | `cwe.workspace_autorun.claude_hook` | `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks/*` | a settings `hooks` entry with a `command`, or a hook script that shells out (`sh -c`, `eval`, `curl … \| sh`) | **CWE-506** |

- **CWE split**: the four rules whose trigger is "this runs because the project was opened" emit **CWE-506** (Embedded Malicious Code). The devcontainer rules emit **CWE-829** (Inclusion of Functionality from an Untrusted Control Sphere): a lifecycle command provisions the workspace from an image, a registry or a fetched install script the developer does not control.
- **JSONC**: `tasks.json`, `settings.json`, `devcontainer.json` and Claude settings legally carry `//` and `/* */` comments and trailing commas, all three of which `json.loads` rejects. The skill strips them (string literals preserved) before parsing, so a task cannot be hidden behind one `//`.
- **Line attribution**: line numbers are recovered from the RAW text, not from the parsed document — a finding must cite the line that executes (the reference incident is `.vscode/tasks.json:7`, the `"command"` line), and JSON parsing discards positions. A second task with its own `command` lands on its own line rather than re-citing the first.
- **`code_snippet`**: the COMMAND text (capped at 400 chars), not a source window. The thing a reviewer has to judge is the text that will run.
- **False-positive discipline**: un-pruning a directory that nearly every repository carries is only defensible if what comes back is the autorun class and nothing else. A `.vscode/settings.json` holding only editor preferences, a task without `folderOpen`, a literal `terminal.integrated.env` value, an ordinary `workspace.xml`, a devcontainer with no lifecycle hook and an inert hook script all produce **zero** findings; each has its own test.
- **Scope reporting**: the walker enters an editor directory only to reach these files, and reports everything else in it — the unread files and the sub-directories — through `pruned_dirs()` at that granularity. The container itself is deliberately NOT reported: the backend's scope check is a prefix match, so a bare `.vscode` would put the file that WAS read out of scope, and an out-of-scope lineage row returns before the tier rules and could never close. See `shared/tests/unit/test_0091_editor_config_scope.py`.
- **Rollback**: `VULTURE_SCAN_EDITOR_CONFIG=false` prunes the editor directories in full again, exactly as before feature 0091. The container becomes the reported prefix, every path beneath it is correctly out of scope, and this skill reports nothing from them.

## Self-Learning (LLM Phase)

When the LLM phase is enabled (`VULTURE_USE_LLM=true`), the agent augments skill findings with:
- **Catalog context injection**: Top 80 static-detectable CWEs injected as structured LLM context
- **Self-learning protocol**: Prior findings with prove_status drive confidence adjustment
  - BOOST: Patterns similar to previously verified findings get higher confidence
  - DEMOTE: Patterns similar to previously not-reproduced findings get lower confidence
  - SKIP: Known issues from memory are excluded to avoid redundancy
- **MMR-based memory retrieval**: Maximal Marginal Relevance balances relevance vs diversity
  - Embedding cosine similarity when vectors available, Jaccard title-token fallback
  - Prove agent feedback loop: verified=1.3× boost, not_reproduced=0.6× demotion
  - Staleness decay for older findings
