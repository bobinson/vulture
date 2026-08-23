"""Feature 0070 P7 — web-security group: 8 new detections in `web_security_check`.

RED-phase tests, written before the detectors, and deliberately containing the
shapes a naive implementation gets wrong (each recorded as a measured review
finding, not a guess):

* **CWE-749** — `@JavascriptInterface` is the *hardening* mechanism since API 17,
  so it must never be an anchor on its own; and a fenced Electron snippet in a
  README must not fire (`.md` is in `WHITELIST_EXTENSIONS`, and
  `COMMENT_INDICATORS` does not match markdown body text).
* **CWE-1022** — real anchors are prettier-formatted with `href` on the line
  *before* `target`, so a forward-only window is a silent recall failure
  (measured: href visible in a forward slice at 5 of 15 sites, in the whole tag
  at 15/15).
* **CWE-315** — the cookie NAME is the subject; `password_changed_at` /
  `x-pwd-reset` are password *workflow* cookies that store no password.
* **CWE-940** — plugin/webview envelopes (Figma, VS Code, extensions) receive at
  origin `null` by design; that was the only surviving window-scoped listener in
  the review corpus and it is a false positive.
* **CWE-784 / CWE-565** — one weakness, split by whether the privileged cookie
  read drives a branch. The XOR invariant is asserted, because skill findings are
  NOT deduplicated against each other (P5) and browser accessors
  (`Cookies.get`) are not server-side security decisions.
* **CWE-539** — the discriminator is lifetime MAGNITUDE. A bounded `maxAge` is
  the *recommended* shape, and the row must not stack on a line that already
  produced CWE-1004/614/1275.
* **CWE-644** — the header source must be receiver-anchored (`response.getHeader`
  is not attacker-controlled), and bare `print` is Python's console sink, which
  belongs to CWE-117.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from cwe_agent.skills.web_security_check import check_web_security


def _run(files: dict[str, str]) -> list[dict]:
    """Materialise `files` (relative path -> body) and run the skill."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_web_security(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


def _cwes(findings: list[dict]) -> set[str]:
    return {f["category"] for f in findings}


# A fully-attributed cookie: HttpOnly + Secure + SameSite=Strict, so CWE-1004,
# CWE-614 and CWE-1275 all stay silent and the CWE-539 magnitude test is what
# the fixture actually exercises.
_ATTRS = "httpOnly: true, secure: true, sameSite: 'strict'"


# ---------------------------------------------------------------------------
# CWE-749 — Exposed Dangerous Method or Function
# ---------------------------------------------------------------------------
class TestExposedDangerousMethod:
    def test_webview_bridge_reported(self):
        f = _run({"bridge.kt": (
            "class Screen {\n"
            "    fun setup(web: WebView) {\n"
            "        web.addJavascriptInterface(Bridge(), \"native\")\n"
            "    }\n"
            "}\n"
        )})
        assert len(_of(f, "CWE-749")) == 1

    def test_webview_clean_twin_not_reported(self):
        """Minimal twin: the bridge is never bound into the page."""
        f = _run({"bridge.kt": (
            "class Screen {\n"
            "    fun setup(web: WebView) {\n"
            "        web.settings.javaScriptEnabled = false\n"
            "    }\n"
            "}\n"
        )})
        assert _of(f, "CWE-749") == []

    def test_annotation_alone_is_not_an_anchor(self):
        """@JavascriptInterface is the API-17+ hardening mechanism, not the
        weakness: a bridge class with no binding call must not be reported."""
        f = _run({"bridge.kt": (
            "class Bridge {\n"
            "    @JavascriptInterface\n"
            "    fun getToken(): String = token\n"
            "}\n"
        )})
        assert _of(f, "CWE-749") == []

    def test_electron_node_integration_reported(self):
        f = _run({"main.js": (
            "const win = new BrowserWindow({\n"
            "  webPreferences: { nodeIntegration: true, contextIsolation: false },\n"
            "});\n"
        )})
        rows = _of(f, "CWE-749")
        assert len(rows) == 1, "one row per file"
        assert rows[0]["severity"] == "high"

    def test_electron_hardened_twin_not_reported(self):
        f = _run({"main.js": (
            "const win = new BrowserWindow({\n"
            "  webPreferences: { nodeIntegration: false, contextIsolation: true },\n"
            "});\n"
        )})
        assert _of(f, "CWE-749") == []

    def test_readme_snippet_does_not_fire(self):
        """`.md` is scanned (WHITELIST_EXTENSIONS) and a fenced snippet carries
        no comment marker — the prose guard is what stops it."""
        f = _run({"README.md": (
            "# Electron security\n"
            "\n"
            "```js\n"
            "webPreferences: { nodeIntegration: true }\n"
            "```\n"
        )})
        assert _of(f, "CWE-749") == []

    def test_docs_path_segment_does_not_fire(self):
        f = _run({"docs/example.js": "webPreferences: { nodeIntegration: true }\n"})
        assert _of(f, "CWE-749") == []


# ---------------------------------------------------------------------------
# CWE-1022 — Use of Web Link to Untrusted Target with window.opener Access
# ---------------------------------------------------------------------------
# CWE-1022 (window.open / target=_blank without noopener) was REVERTED after
# measurement. Its 5 rows on a real tree were all false: same-origin
# `window.open` of a generated document, and anchors to fixed trusted hosts.
# The LLD's "Killed — do not re-propose" register had already recorded exactly
# this outcome, and modern browsers imply noopener for target=_blank anyway.



class TestCleartextCookiePayload:
    def test_password_cookie_reported(self):
        f = _run({"login.js": "res.cookie('password', body.password, opts);\n"})
        rows = _of(f, "CWE-315")
        assert len(rows) == 1
        assert rows[0]["check_id"] == "cwe.web_security.cleartext_cookie_payload"

    def test_session_cookie_clean_twin(self):
        """Minimal twin: the same sink with a non-sensitive name."""
        f = _run({"login.js": "res.cookie('sid', body.sid, opts);\n"})
        assert _of(f, "CWE-315") == []

    def test_password_workflow_name_not_reported(self):
        for name in ("password_changed_at", "x-pwd-reset", "password_reset_token",
                     "password_expired", "password_policy"):
            f = _run({"login.js": f"res.cookie('{name}', v, opts);\n"})
            assert _of(f, "CWE-315") == [], name

    def test_hashed_name_not_reported(self):
        f = _run({"login.js": "res.cookie('password_hash', h, opts);\n"})
        assert _of(f, "CWE-315") == []

    def test_encrypted_line_not_reported(self):
        f = _run({"login.js": "res.cookie('password', encrypt(pw), opts);\n"})
        assert _of(f, "CWE-315") == []

    def test_doc_extension_not_reported(self):
        f = _run({"COOKIES.md": "res.cookie('password', pw)\n"})
        assert _of(f, "CWE-315") == []

    def test_python_and_php_sinks(self):
        assert len(_of(_run({"v.py": "resp.set_cookie('ssn', ssn)\n"}), "CWE-315")) == 1
        assert len(_of(_run({"v.php": "setcookie('cvv', $cvv);\n"}), "CWE-315")) == 1

    def test_check_id_distinct_from_attribute_checks(self):
        f = _run({"login.js": "res.cookie('password', pw);\n"})
        ids = {x["check_id"] for x in f}
        assert "cwe.web_security.cleartext_cookie_payload" in ids
        assert len({i for i in ids if i.startswith("cwe.web_security.cookie_")}) >= 1


# ---------------------------------------------------------------------------
# CWE-940 — Improper Verification of Source of a Communication Channel
# ---------------------------------------------------------------------------
class TestMessageOriginVerification:
    LISTENER = (
        "window.addEventListener('message', (event) => {\n"
        "  const data = event.data;\n"
        "  render(data.html);\n"
        "});\n"
    )

    def test_window_listener_without_origin_check_reported(self):
        assert len(_of(_run({"app.js": self.LISTENER}), "CWE-940")) == 1

    def test_origin_check_clean_twin(self):
        body = (
            "window.addEventListener('message', (event) => {\n"
            "  if (event.origin !== 'https://trusted.example') return;\n"
            "  render(event.data.html);\n"
            "});\n"
        )
        assert _of(_run({"app.js": body}), "CWE-940") == []

    def test_non_window_receiver_not_reported(self):
        body = (
            "this.ws.addEventListener('message', (ev) => {\n"
            "  this.handleMessage(ev.data);\n"
            "});\n"
        )
        assert _of(_run({"gateway.ts": body}), "CWE-940") == []

    def test_bare_identifier_handler_not_reported(self):
        body = "window.addEventListener('message', handleMessage);\n"
        assert _of(_run({"app.js": body}), "CWE-940") == []

    def test_plugin_envelope_suppressed(self):
        """A Figma plugin UI iframe receives at origin `null` by design; the
        `pluginMessage` envelope IS the platform contract."""
        body = (
            "window.onmessage = (event) => {\n"
            "  const msg = event.data.pluginMessage;\n"
            "  render(msg);\n"
            "};\n"
        )
        assert _of(_run({"ui.html": body}), "CWE-940") == []

    def test_vscode_webview_suppressed(self):
        body = (
            "const vscode = acquireVsCodeApi();\n"
            "window.addEventListener('message', (event) => {\n"
            "  apply(event.data);\n"
            "});\n"
        )
        assert _of(_run({"webview.js": body}), "CWE-940") == []


# ---------------------------------------------------------------------------
# CWE-784 / CWE-565 — cookie reliance (decision vs non-decision)
# ---------------------------------------------------------------------------
class TestCookieReliance:
    def test_branch_on_cookie_is_784(self):
        f = _run({"h.js": "if (req.cookies.isAdmin) { grantAll(); }\n"})
        assert len(_of(f, "CWE-784")) == 1
        assert _of(f, "CWE-565") == [], "784 XOR 565 on one line"

    def test_dot_get_accessor_form_is_reached(self):
        """`req.cookies.get('role')` / `request.COOKIES.get(...)` is the dominant
        Express/Django form; a connector of only `[`, `(` or `.` misses it."""
        f = _run({"h.js": "if (req.cookies.get('isAdmin')) { grantAll(); }\n"})
        assert len(_of(f, "CWE-784")) == 1
        g = _run({"h.py": "role = request.COOKIES.get('role')\nrender(role)\n"})
        assert len(_of(g, "CWE-565")) == 1

    def test_comparison_on_cookie_is_784(self):
        f = _run({"h.py": "allowed = request.COOKIES['role'] == 'admin'\n"})
        assert len(_of(f, "CWE-784")) == 1
        assert _of(f, "CWE-565") == []

    def test_bound_read_is_565(self):
        f = _run({"h.js": "const role = req.cookies.role;\n"})
        assert len(_of(f, "CWE-565")) == 1
        assert _of(f, "CWE-784") == []

    def test_passed_read_is_565(self):
        f = _run({"h.php": "authorize($_COOKIE['user_id']);\n"})
        assert len(_of(f, "CWE-565")) == 1
        assert _of(f, "CWE-784") == []

    def test_clean_twin_non_privileged_name(self):
        """Minimal twin: same accessor and shape, benign cookie name."""
        f = _run({"h.js": "if (req.cookies.locale) { setLang(); }\n"})
        assert _cwes(f) & {"CWE-784", "CWE-565"} == set()

    def test_browser_accessor_not_reported(self):
        """`js-cookie` is browser-only; a nav-rendering read is not a
        server-side security decision (its honest label, CWE-602, is out of
        scope)."""
        for body in ("if (Cookies.get('role') === 'admin') { show(); }\n",
                     "const r = document.cookie;\n",
                     "if (getCookie('isAdmin')) { show(); }\n"):
            f = _run({"nav.js": body})
            assert _cwes(f) & {"CWE-784", "CWE-565"} == set(), body

    def test_jsx_render_guard_not_reported(self):
        """`&&` / `?` are not decision predicates — dropped from the anchors."""
        f = _run({"nav.jsx": "const el = user && Cookies.get('role') && <Admin/>;\n"})
        assert _cwes(f) & {"CWE-784", "CWE-565"} == set()

    def test_signed_cookie_not_reported(self):
        f = _run({"h.js": "if (req.signedCookies.isAdmin) { grantAll(); }\n"})
        assert _cwes(f) & {"CWE-784", "CWE-565"} == set()

    def test_verifier_in_window_not_reported(self):
        body = (
            "const raw = req.cookies.role;\n"
            "const claims = jwt.verify(raw, secret);\n"
        )
        assert _cwes(_run({"h.js": body})) & {"CWE-784", "CWE-565"} == set()

    def test_one_row_per_file_and_name(self):
        body = (
            "if (req.cookies.isAdmin) { a(); }\n"
            "if (req.cookies.isAdmin) { b(); }\n"
        )
        assert len(_of(_run({"h.js": body}), "CWE-784")) == 1

    def test_admin_name_is_high_severity(self):
        rows = _of(_run({"h.js": "if (req.cookies.isAdmin) { a(); }\n"}), "CWE-784")
        assert rows[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# CWE-539 — Use of Persistent Cookies Containing Sensitive Information
# ---------------------------------------------------------------------------
class TestPersistentCookie:
    def test_long_lived_sensitive_cookie_reported(self):
        f = _run({"auth.js": (
            "res.cookie('remember_token', t, {\n"
            f"  maxAge: 31536000000, {_ATTRS},\n"
            "});\n"
        )})
        rows = _of(f, "CWE-539")
        assert len(rows) == 1
        assert rows[0]["severity"] == "low"

    def test_bounded_lifetime_clean_twin(self):
        """The recommended shape: a bounded (1h) lifetime. Differs from the
        positive only in the magnitude."""
        f = _run({"auth.js": (
            "res.cookie('remember_token', t, {\n"
            f"  maxAge: 3600000, {_ATTRS},\n"
            "});\n"
        )})
        assert _of(f, "CWE-539") == []

    def test_seconds_threshold(self):
        f = _run({"auth.py": (
            "resp.set_cookie('session_token', t, max_age=31536000,\n"
            "                httponly=True, secure=True, samesite='Strict')\n"
        )})
        assert len(_of(f, "CWE-539")) == 1

    def test_not_stacked_on_attribute_findings(self):
        """A bare cookie write already yields CWE-1004 + 614 + 1275; CWE-539
        must not make it four rows (P5)."""
        f = _run({"auth.js": "res.cookie('remember_token', t, { maxAge: 31536000000 });\n"})
        assert _of(f, "CWE-539") == []
        assert "CWE-1004" in _cwes(f)

    def test_non_sensitive_name_not_reported(self):
        f = _run({"auth.js": (
            "res.cookie('theme', t, {\n"
            f"  maxAge: 31536000000, {_ATTRS},\n"
            "});\n"
        )})
        assert _of(f, "CWE-539") == []

    def test_capped_at_one_row_per_file(self):
        body = (
            f"res.cookie('remember_token', a, {{ maxAge: 31536000000, {_ATTRS} }});\n"
            f"res.cookie('auth_token', b, {{ maxAge: 31536000000, {_ATTRS} }});\n"
        )
        assert len(_of(_run({"auth.js": body}), "CWE-539")) == 1


# ---------------------------------------------------------------------------
# CWE-644 — Improper Neutralization of HTTP Headers for Scripting Syntax
# ---------------------------------------------------------------------------
class TestHeaderScriptingSyntax:
    def test_php_echo_of_header_reported(self):
        f = _run({"v.php": "echo $_SERVER['HTTP_USER_AGENT'];\n"})
        assert len(_of(f, "CWE-644")) == 1

    def test_php_escaped_twin_not_reported(self):
        f = _run({"v.php": "echo htmlspecialchars($_SERVER['HTTP_USER_AGENT']);\n"})
        assert _of(f, "CWE-644") == []

    def test_node_response_send_reported(self):
        f = _run({"v.js": "res.send('<p>' + req.headers['x-forwarded-for'] + '</p>');\n"})
        assert len(_of(f, "CWE-644")) == 1

    def test_response_getheader_is_not_a_source(self):
        """A RESPONSE header read is not attacker-controlled — the receiver
        anchor is what rejects it."""
        f = _run({"V.java": "resp.getWriter().print(response.getHeader(\"X-Trace\"));\n"})
        assert _of(f, "CWE-644") == []

    def test_java_request_getheader_reported(self):
        f = _run({"V.java": "resp.getWriter().print(request.getHeader(\"X-Trace\"));\n"})
        assert len(_of(f, "CWE-644")) == 1

    def test_python_print_is_not_a_sink(self):
        """Bare `print` is Python's console sink; a header written to a log is
        CWE-117, which is corpus-VERIFIED elsewhere."""
        f = _run({"v.py": "print(request.META['HTTP_USER_AGENT'])\n"})
        assert _of(f, "CWE-644") == []

    def test_source_without_sink_not_reported(self):
        f = _run({"v.js": "const ua = req.headers['user-agent'];\n"})
        assert _of(f, "CWE-644") == []


# ---------------------------------------------------------------------------
# Attestation: every new CWE is emitted with a LITERAL category (P0/rule 8).
# ---------------------------------------------------------------------------
def test_new_categories_are_source_literals():
    import re

    from cwe_agent.skills import web_security_check

    src = Path(web_security_check.__file__).read_text()
    literals = set(re.findall(r'"category":\s*"CWE-(\d+)"', src))
    for cwe in ("749", "1022", "315", "940", "784", "565", "539", "644"):
        assert cwe in literals, f"CWE-{cwe} must be a literal, not an f-string"
