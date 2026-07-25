"""Shared `$VAR` / `${VAR}` reference detection for credential checks.

Many CI YAML files, shell scripts, and Helm/Jinja templates assign
secrets via env-var or template-variable indirection:

    STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"
    --build-arg API_KEY="$CONGRESS_API_KEY"
    PGPASSWORD="${POSTGRES_PASSWORD}"
    api_key: '%(SECRET_KEY)s'
    token: {{ .Values.apiKey }}

These look like hardcoded secrets to a substring matcher but are
actually safe — the literal value is a pointer to a runtime-injected
variable. This module centralises the detection so every credential-
shaped detector (auth_check / info_exposure_check / crypto_check)
can suppress them consistently.

The same pattern lives in
``cwe_agent.skills.secret_scan.config_files`` for the structured
config-file scanner; this is the line-oriented variant for raw source.
"""

from __future__ import annotations

import re


# Match any common variable-indirection shape inside a quoted string.
# The line-oriented detectors call this against a captured RHS like
#   `password = "$VAR"` → captured value `$VAR`
#   `api_key = '${SECRET}'` → captured value `${SECRET}`
# An optional surrounding quoted string wrapping is also accepted, so
# we can hand the raw matched substring (including quotes) and still
# match.
_VAR_REF_RE = re.compile(
    r"""
    ^                                       # start
    \s*
    ["']?                                   # optional opening quote
    \s*
    (?:
        \$\{[A-Za-z_][\w]*(?::-[^}]*)?\}    # ${VAR} or ${VAR:-default}
      | \$[A-Za-z_][\w]*                    # $VAR
      | \$\([^)]+\)                         # $(command substitution)
      | %\([A-Za-z_][\w]*\)[sdifrx]?        # %(VAR)s configparser
      | <%=\s*[A-Za-z_][\w]*\s*%>           # ERB <%= VAR %>
      | \{\{\s*[\w.\-]+\s*\}\}              # Jinja / Helm {{ VAR }}
      | \{\{-?\s*[\w.\-]+\s*-?\}\}          # whitespace-trimmed Helm
      | \$\$[A-Za-z_][\w]*                  # docker-compose $$VAR escape
    )
    \s*
    ["']?                                   # optional closing quote
    \s*$
    """,
    re.VERBOSE,
)


def is_variable_reference(value: str) -> bool:
    """True when ``value`` (a stripped RHS string) is a variable
    reference rather than a literal secret. Whitespace and the
    surrounding quote characters are tolerated."""
    if not value:
        return False
    return bool(_VAR_REF_RE.match(value))


# Captures the RHS of common credential-assignment shapes so callers
# can hand the captured group to ``is_variable_reference``. Covers:
#   foo = "..."           Python / TypeScript / JS / Ruby
#   foo: "..."            YAML
#   foo := "..."          Go
#   --foo=...             flag assignment (no quotes required)
#   --foo "..."
#   -e FOO="..."          docker exec env-var pass
#   ENV FOO=...           Dockerfile
_RHS_CAPTURE = re.compile(
    r"""
    [=:]                                  # = or : separator
    \s*
    (?P<rhs>
        "(?:\\.|[^"\\])*"                 # double-quoted
      | '(?:\\.|[^'\\])*'                 # single-quoted
      | \$\{[^}]+\}                       # ${VAR}
      | \$[A-Za-z_][\w]*                  # $VAR (unquoted)
      | %\([\w]+\)[sdifrx]?               # %(VAR)s
      | \{\{[^}]+\}\}                     # {{ VAR }}
    )
    """,
    re.VERBOSE,
)


def line_value_is_variable_ref(line: str) -> bool:
    """True when the credential-shaped RHS on ``line`` is a variable
    reference. Used by line-oriented detectors that already matched
    the credential pattern and want to suppress before emitting."""
    m = _RHS_CAPTURE.search(line)
    if m is None:
        return False
    return is_variable_reference(m.group("rhs"))
