"""CWE-117 — Improper output neutralization for logs (log injection).

Sink: a logging call (log/logger/logrus/console.log) whose message is built by
concatenating / interpolating an untrusted value, with no CRLF-stripping /
encoding in the window. ``require_source=True``.

Bounded quantifiers (ReDoS-safe).
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

LOG_SINK = re.compile(
    r"(?:log\.(?:info|warn|warning|error|debug|trace)|logger\.\w{1,20}|"
    r"logrus\.\w{1,20}|console\.(?:log|info|warn|error)|"
    r"System\.out\.print(?:ln)?|Log\.\w{1,20})\s*\("
    r"[^\n]{0,200}(?:\+|%s|\$\{|\{\}|f[\"'])"
)
LOG_SOURCE = re.compile(
    r"\b(?:request|req)\b|getParameter\(|\.args\b|\.params\b|\.query\b|"
    r"\binput\b|\buser\b|\.body\b|\bparam\b",
    re.IGNORECASE,
)
LOG_SANITIZER = re.compile(
    r"replace\([^)\n]{0,40}(?:\\r|\\n|\\R)|encode\(|sanitize\(|"
    r"escapeJava|StringEscapeUtils|strip\(|replaceAll\([^)\n]{0,40}\\[rn]|"
    r"CRLFLogConverter|encodeForHTML",
    re.IGNORECASE,
)

SIGNATURES = (
    CweSignature(
        cwe_id="117",
        sig_id="cwe.sig.loginj",
        title="Log injection: untrusted input logged without neutralization",
        severity="medium",
        languages=("Java", "Python", "JavaScript", "TypeScript", "Go"),
        sink=LOG_SINK,
        source=LOG_SOURCE,
        sanitizer=LOG_SANITIZER,
        require_source=True,
        confidence=0.55,
        status="trusted",
    ),
)
