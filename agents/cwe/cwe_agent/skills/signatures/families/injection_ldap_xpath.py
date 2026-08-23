"""CWE-90 (LDAP injection) + CWE-91 (XPath injection).

Both are tainted-source signatures: a query/filter sink built by string
interpolation, fed by an untrusted source within the window, NOT neutralised
by an encoder/parameteriser. ``require_source=True`` — a sink built from a
constant must NOT fire.

All quantifiers are bounded (``[^)\n]{0,200}`` etc.) for ReDoS-safety.
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

# A tainted, attacker-controllable source. Shared by LDAP + XPath.
_TAINTED_SOURCE = re.compile(
    r"\b(?:request|req)\b|getParameter\(|\.args\b|\.params\b|\.query\b|"
    r"\binput\b|\buser\b|\bpayload\b|\bbody\b",
    re.IGNORECASE,
)

# ── CWE-90: LDAP injection ────────────────────────────────────────────
# Sink: an LDAP filter built with string interpolation/concat near an LDAP
# search/context API. Two complementary shapes:
#   (a) an LDAP-specific search/context call:  ctx.search( , InitialDirContext( ,
#       ldap.search( , search_s( / search_ext_s( (python-ldap), DirContext.
#       NOTE: the bare ``\bsearch\s*\(`` token is deliberately NOT used — it
#       over-matched every non-LDAP ``.search(`` (re.search, Elasticsearch
#       client.search, list.search) and produced false positives (0057 review).
#       The LDAP-specific receivers below carry the real signal; the precise
#       ``_LDAP_FILTER`` branch already catches concat-built filters, so recall
#       is unaffected.
#   (b) a filter literal "(attr=" concatenated/interpolated with a variable.
#
# PRECISION (feature 0070): branch (b) used to accept a BARE parenthesis —
# ``\(\s*ident\s*=`` followed anywhere by ``{`` — so every JS arrow function
# (``(user = {}) =>``, ``card => {``, ``prev => [...]``) and every ``===``
# chain read as an LDAP filter. Measured: 4 rows, 4 false, on a
# codebase with no LDAP anywhere. An LDAP filter is a *string*, so both the
# concat and the interpolation branch now anchor on the opening quote of the
# literal (optionally preceded by an f/b/r/u string prefix) and the scan for
# the placeholder stays INSIDE that literal (``[^"'`\n]``), never crossing a
# quote. Recall is unaffected: the shapes that matter — ``"(uid=" + x``,
# ``'(uid=' + x``, f-strings, template literals, ``%s`` / ``%(k)s`` /
# ``{}``.format placeholders — are all quoted by construction.
_LDAP_QUOTE = r"(?:[fFbBrRuU]{0,2}[\"'`])"
_LDAP_ATTR = r"[A-Za-z][A-Za-z0-9_-]{0,40}"
_LDAP_FILTER = (
    # (b1) quoted filter literal concatenated with a variable: "(uid=" + x
    rf'"\(\s*{_LDAP_ATTR}\s*=[^"\n]{{0,200}}"\s*[+%]'
    rf"|'\(\s*{_LDAP_ATTR}\s*=[^'\n]{{0,200}}'\s*[+%]"
    # (b2) quoted filter literal carrying an interpolation placeholder:
    #      f"(cn={name})" / `(uid=${x})` / "(uid=%s)" / '(uid=%(k)s)'
    rf"|{_LDAP_QUOTE}\(\s*{_LDAP_ATTR}\s*=[^\"'`\n]{{0,200}}"
    r"(?:\$\{|\{|%s|%\()"
)
LDAP_SINK = re.compile(
    r"(?:InitialDirContext|DirContext|NamingEnumeration|"
    r"ldap(?:_search|\.search)|"
    r"\bctx\.search\s*\(|\bsearch_(?:s|ext_s)\s*\()[^\n]{0,200}|"
    rf"{_LDAP_FILTER}"
)
LDAP_SANITIZER = re.compile(
    r"encodeForLDAP|escapeLDAP|escapeDN|filterEncode|"
    r"LdapEncoder|escape_filter_chars|escape_dn_chars",
    re.IGNORECASE,
)

# ── CWE-91: XPath injection ───────────────────────────────────────────
# Sink: an XPath evaluate/compile/selectNodes call built with concat/interp.
_XPATH_CALL = (
    r"\.(?:evaluate|compile|selectNodes|selectSingleNode|xpath)\s*\("
    r"|XPathExpression|createExpression\("
)
XPATH_SINK = re.compile(
    rf"(?:{_XPATH_CALL})[^\n]{{0,200}}(?:\+|\$\{{|%s|\{{|f[\"'])"
)
XPATH_SANITIZER = re.compile(
    r"XPathVariableResolver|setXPathVariable|setVariable\(|"
    r"escapeXPath|XPathConstants",
    re.IGNORECASE,
)

SIGNATURES = (
    CweSignature(
        cwe_id="90",
        sig_id="cwe.sig.ldap",
        title="LDAP injection: filter built from untrusted input",
        severity="high",
        languages=("Java", "Python", "JavaScript", "TypeScript", "PHP", "C#"),
        sink=LDAP_SINK,
        source=_TAINTED_SOURCE,
        sanitizer=LDAP_SANITIZER,
        require_source=True,
        confidence=0.6,
        status="trusted",
    ),
    CweSignature(
        cwe_id="91",
        sig_id="cwe.sig.xpath",
        title="XPath injection: expression built from untrusted input",
        severity="high",
        languages=("Java", "Python", "JavaScript", "TypeScript", "C#", "PHP"),
        sink=XPATH_SINK,
        source=_TAINTED_SOURCE,
        sanitizer=XPATH_SANITIZER,
        require_source=True,
        confidence=0.6,
        status="trusted",
    ),
)
