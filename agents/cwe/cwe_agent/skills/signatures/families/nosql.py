"""CWE-943 — NoSQL injection (MongoDB-style query operators and selectors).
Complements CWE-89, which only covers SQL.

Three sibling signatures, all ``cwe_id="943"``, split because they need
DIFFERENT sanitizers (feature 0070):

  1. ``cwe.sig.nosql_where``    — a JavaScript-predicate operator (``$where`` /
     ``$function`` / ``$accumulator`` / ``mapReduce``) fed by untrusted input.
     Only a *numeric coercion* (or a real sanitizer) neutralises this; a
     ``String(...)`` cast does NOT — the value is still concatenated into a
     JavaScript predicate the server evaluates. Sharing one sanitizer list
     with the selector branch below silently hid a real finding
     (``$where: `…'${id}'` `` where ``id = String(req.params.id)``).
  2. ``cwe.sig.nosql``          — an untrusted value reaching a ``$``-operator
     inside a *query selector object*. Here a cast (``Number``/``String``/
     ``ObjectId``) or ``$eq`` genuinely neutralises operator injection, so the
     original sanitizer list is correct and kept.
  3. ``cwe.sig.nosql_mutation`` — a **mutating** collection operation
     (``update``/``updateOne``/``updateMany``/``replaceOne``/
     ``findOneAndUpdate``/``remove``/``deleteOne``/``deleteMany`` and their
     PyMongo snake_case spellings) whose selector is built from untrusted
     input. These were not sinks at all, yet they are the highest-impact
     shape: an attacker who smuggles ``{"$ne": -1}`` into the selector
     rewrites or deletes *every* document. The receiver is
     required to be collection-ish (``…Collection``, ``db.<name>``,
     ``db.collection("…")``) so Sequelize/ORM ``model.update({...})`` and
     stream ``hmac.update(data)`` / ``fs.remove(f)`` are NOT sinks.

OWASP: CWE-943 is **not mapped by any OWASP 2025 category** (verified against
``shared/owasp/editions/owasp_2025.json``; it is absent from the 2021 edition
too). The titles say so explicitly so a report never implies a category the
edition does not carry.

All quantifiers are bounded (ReDoS-safe); the matcher additionally length-caps
every line.
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

# Appended to every title: CWE-943 has no OWASP 2025 category, and the finding
# must state that rather than imply one.
_OWASP_NOTE = "no OWASP 2025 category maps CWE-943"

# ── shared tainted source ─────────────────────────────────────────────
NOSQL_SOURCE = re.compile(
    r"\b(?:req|request)\b|\.body\b|\.query\b|\.params\b|"
    r"\binput\b|\buser\b|\bparam\b|getParameter\(",
    re.IGNORECASE,
)

# ── 1. JavaScript-predicate operators ─────────────────────────────────
WHERE_SINK = re.compile(
    r"\$where\b|\$function\b|\$accumulator\b|\.mapReduce\s*\(|"
    r"\.map_reduce\s*\("
)
# Only a numeric coercion (an injected predicate cannot survive Number/int) or
# a real NoSQL sanitizer neutralises a JS predicate. Deliberately EXCLUDES
# String()/escape()/$eq/ObjectId(): those protect a selector, not a predicate.
WHERE_SANITIZER = re.compile(
    r"mongo-?sanitize|Number\s*\(|Number\.isInteger|parseInt\s*\(|"
    r"parseFloat\s*\(|\bint\s*\(|\bfloat\s*\(|\bDecimal\s*\(",
    re.IGNORECASE,
)

# ── 2. selector-object operator injection ─────────────────────────────
# NOTE (0057 review): the generic ``.find({ ... req ... })`` branch was
# restricted to *operator-injection* shapes. The previous form fired on benign
# field-equality lookups (``User.find({ _id: req.params.id })``, a parameterised
# query, and even plain JS ``Array.find``). NoSQL injection is the case where an
# untrusted value reaches a ``$``-operator/key — so the find-object branch
# requires a ``$``-operator near the untrusted token inside the object.
NOSQL_SINK = re.compile(
    # untrusted value spread/assigned directly into a query operator object
    r"\$\s*:\s*(?:req|input|user|param|body)|"
    # find({...}) where a $-operator and an untrusted token co-occur in the obj
    r"\.find\s*\(\s*\{[^}\n]{0,200}\$[A-Za-z]{1,20}[^}\n]{0,200}"
    r"(?:req|input|user|param|body|query)|"
    r"\.find\s*\(\s*\{[^}\n]{0,200}(?:req|input|user|param|body|query)"
    r"[^}\n]{0,200}\$[A-Za-z]{1,20}"
)
NOSQL_SANITIZER = re.compile(
    r"mongo-?sanitize|sanitize\(|\$eq\b|ObjectId\(|"
    r"Number\(|parseInt\(|String\(|escape\(",
    re.IGNORECASE,
)

# ── 3. mutating collection operations ─────────────────────────────────
# Receiver must be collection-ish, else every ORM/stream ``.update(`` is a sink.
_COLLECTION_RECEIVER = (
    r"(?:[A-Za-z_$][\w$]{0,40})?[Cc]ollection"
    r"|\bdb\.[A-Za-z_$][\w$]{0,40}"
    r"|\.collection\s*\(\s*[\"'][\w.$-]{1,60}[\"']\s*\)"
)
_MUTATING_OP = (
    r"update|updateOne|updateMany|replaceOne|findOneAndUpdate|"
    r"findOneAndReplace|findOneAndDelete|findAndModify|remove|deleteOne|"
    r"deleteMany|update_one|update_many|replace_one|find_one_and_update|"
    r"find_one_and_replace|find_one_and_delete|delete_one|delete_many"
)
MUTATION_SINK = re.compile(
    rf"(?:{_COLLECTION_RECEIVER})\s*\.\s*(?:{_MUTATING_OP})\s*\("
)
# A selector IS neutralised by a cast (an injected ``{$ne: …}`` object becomes
# a scalar) or by an explicit type guard — the canonical JS fix.
MUTATION_SANITIZER = re.compile(
    r"mongo-?sanitize|sanitize\s*\(|\$eq\b|ObjectId\(|"
    r"Number\s*\(|parseInt\s*\(|String\s*\(|escape\s*\(|"
    r"typeof\s+[\w.$\[\]'\"]{1,60}\s*[=!]==?\s*[\"']string[\"']|"
    r"isinstance\s*\(",
    re.IGNORECASE,
)
# The selector and the update document usually sit on the lines FOLLOWING the
# call, and a type guard sits a few lines above — wider than the 4-line default.
_MUTATION_WINDOW = 6

SIGNATURES = (
    CweSignature(
        cwe_id="943",
        sig_id="cwe.sig.nosql_where",
        title=(
            "NoSQL injection: $where/mapReduce JavaScript predicate built "
            f"from untrusted input ({_OWASP_NOTE})"
        ),
        severity="high",
        languages=("JavaScript", "TypeScript", "Python", "Java"),
        sink=WHERE_SINK,
        source=NOSQL_SOURCE,
        sanitizer=WHERE_SANITIZER,
        require_source=True,
        confidence=0.6,
        status="trusted",
    ),
    CweSignature(
        cwe_id="943",
        sig_id="cwe.sig.nosql",
        title=(
            "NoSQL injection: query operator/object built from untrusted "
            f"input ({_OWASP_NOTE})"
        ),
        severity="high",
        languages=("JavaScript", "TypeScript", "Python", "Java"),
        sink=NOSQL_SINK,
        source=NOSQL_SOURCE,
        sanitizer=NOSQL_SANITIZER,
        require_source=True,
        confidence=0.55,
        status="trusted",
    ),
    CweSignature(
        cwe_id="943",
        sig_id="cwe.sig.nosql_mutation",
        title=(
            "NoSQL injection: mutating collection operation with an "
            f"uncast selector from untrusted input ({_OWASP_NOTE})"
        ),
        severity="high",
        languages=("JavaScript", "TypeScript", "Python", "Java"),
        sink=MUTATION_SINK,
        source=NOSQL_SOURCE,
        sanitizer=MUTATION_SANITIZER,
        window=_MUTATION_WINDOW,
        require_source=True,
        confidence=0.55,
        status="trusted",
    ),
)
