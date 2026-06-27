"""CWE-943 — NoSQL injection (e.g. MongoDB ``$where`` / ``$function`` and
untrusted query objects). Complements CWE-89, which only covers SQL.

Sink: a ``$where`` / ``$function`` operator, ``mapReduce``, or a ``.find({...})``
query object built from an untrusted value. ``require_source=True``.
A ``$eq``/cast/sanitizer suppresses.

Bounded quantifiers (ReDoS-safe).
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

# NOTE (0057 review): the generic ``.find({ ... req ... })`` branch was
# restricted to *operator-injection* shapes. The previous form fired on benign
# field-equality lookups (``User.find({ _id: req.params.id })``, a parameterised
# query, and even plain JS ``Array.find``). NoSQL injection is the case where an
# untrusted value reaches a ``$``-operator/key — so the find-object branch now
# requires a ``$``-operator near the untrusted token inside the object. The
# high-precision ``$where`` / ``$function`` / ``mapReduce`` branches are kept.
NOSQL_SINK = re.compile(
    r"\$where\b|\$function\b|\.mapReduce\s*\(|"
    # untrusted value spread/assigned directly into a query operator object
    r"\$\s*:\s*(?:req|input|user|param|body)|"
    # find({...}) where a $-operator and an untrusted token co-occur in the obj
    r"\.find\s*\(\s*\{[^}\n]{0,200}\$[A-Za-z]{1,20}[^}\n]{0,200}"
    r"(?:req|input|user|param|body|query)|"
    r"\.find\s*\(\s*\{[^}\n]{0,200}(?:req|input|user|param|body|query)"
    r"[^}\n]{0,200}\$[A-Za-z]{1,20}"
)
NOSQL_SOURCE = re.compile(
    r"\b(?:req|request)\b|\.body\b|\.query\b|\.params\b|"
    r"\binput\b|\buser\b|\bparam\b|getParameter\(",
    re.IGNORECASE,
)
NOSQL_SANITIZER = re.compile(
    r"mongo-?sanitize|sanitize\(|\$eq\b|ObjectId\(|"
    r"Number\(|parseInt\(|String\(|escape\(",
    re.IGNORECASE,
)

SIGNATURES = (
    CweSignature(
        cwe_id="943",
        sig_id="cwe.sig.nosql",
        title="NoSQL injection: query operator/object built from untrusted input",
        severity="high",
        languages=("JavaScript", "TypeScript", "Python", "Java"),
        sink=NOSQL_SINK,
        source=NOSQL_SOURCE,
        sanitizer=NOSQL_SANITIZER,
        require_source=True,
        confidence=0.55,
        status="trusted",
    ),
)
