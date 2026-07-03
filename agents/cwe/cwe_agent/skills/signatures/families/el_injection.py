"""CWE-917 — Expression Language injection (SpEL / OGNL / MVEL). Java-only.

Sink: a SpEL/OGNL/MVEL expression parser fed a string built by concat/interp.
``require_source=True`` — a parser fed a constant expression does not fire.
A scoped/sandboxed evaluation context (``SimpleEvaluationContext``) suppresses.

Bounded quantifiers throughout (ReDoS-safe).
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

# NOTE: the bare ``getValue\s*\(`` alternative was dropped (0057 review): it
# exists on countless non-EL APIs (Map.getValue, Cell.getValue, config.getValue)
# and over-matched. The SpEL/OGNL/MVEL-specific parser tokens below carry the
# real expression-injection signal.
_EL_PARSER = (
    r"(?:SpelExpressionParser|SpelExpression|\.parseExpression\s*\(|"
    r"\bOgnl\.|OgnlUtil|MVEL\.(?:eval|compileExpression)|"
    r"ExpressionParser|ELProcessor)"
)
# The parser call must carry a dynamically-built expression (concat / format /
# template), not a constant string literal.
SPEL_SINK = re.compile(
    rf"{_EL_PARSER}[^\n]{{0,200}}(?:\+|String\.format|\$\{{|%s)"
)
SPEL_SOURCE = re.compile(
    r"\b(?:request|req)\b|getParameter\(|\binput\b|\bpayload\b|"
    r"\buser\b|\.params\b|\.query\b|\bbody\b",
    re.IGNORECASE,
)
SPEL_SANITIZER = re.compile(
    r"SimpleEvaluationContext|setRootObject\(\s*null|"
    r"StandardEvaluationContext\([^)\n]{0,40}\)\s*;\s*$",
)

SIGNATURES = (
    CweSignature(
        cwe_id="917",
        sig_id="cwe.sig.spel",
        title="Expression Language injection (SpEL/OGNL/MVEL) from untrusted input",
        severity="critical",
        languages=("Java",),
        sink=SPEL_SINK,
        source=SPEL_SOURCE,
        sanitizer=SPEL_SANITIZER,
        require_source=True,
        confidence=0.6,
        status="trusted",
    ),
)
