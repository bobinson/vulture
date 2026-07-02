"""CWE-1333 — Inefficient Regular Expression Complexity (ReDoS).

Zero-dataflow, structural signature (the strongest in the tranche): a regex
literal / constructor whose body contains a *nested or overlapping unbounded
quantifier* — the classic catastrophic-backtracking shape ``(a+)+`` /
``(.*)*`` / ``(x+)+y``. No tainted source required.

ReDoS-safety of OUR OWN regex (invariant): the nested-quantifier detector is
written with BOUNDED character-class repetition (``[^)\n]{0,200}``) instead of
the catastrophic ``[^)]*`` shape, and the detector length-caps every line
before matching, so these patterns cannot themselves backtrack catastrophically.
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

# A regex constructor / literal context: new RegExp(, re.compile(,
# Pattern.compile(, regexp.MustCompile(, or a /.../ literal assignment.
_RX_CTOR = (
    r"(?:new\s+RegExp\(|re\.compile\(|Pattern\.compile\(|"
    r"regexp\.(?:MustCompile|Compile)\(|=\s*/)"
)

# Nested unbounded quantifier: a group whose body ends in +/* and is itself
# followed by +/*  — e.g. (a+)+ , (\d+)* , (?:ab+)+ . Bounded inner class
# {0,200} keeps it ReDoS-safe; the trailing quantifier (after the group close)
# is what makes the *source regex under audit* catastrophic.
_NESTED_QUANT = r"\((?:\?:)?[^)\n]{0,200}[+*]\)[+*]"

# Overlapping alternation of unbounded wildcards, e.g. (.*|.+){2,} or (.*)*.
_OVERLAP = r"\((?:\.\*|\.\+)\)[+*]|\((?:\.\*|\.\+)(?:\|(?:\.\*|\.\+))+\)\{?\d*,?"

REDOS_SINK = re.compile(
    rf"{_RX_CTOR}[^\n]{{0,200}}(?:{_NESTED_QUANT}|{_OVERLAP})"
)

SIGNATURES = (
    CweSignature(
        cwe_id="1333",
        sig_id="cwe.sig.redos",
        title="Inefficient regular expression (ReDoS): nested unbounded quantifier",
        severity="high",
        languages=("JavaScript", "TypeScript", "Python", "Java", "Go"),
        sink=REDOS_SINK,
        require_source=False,
        confidence=0.65,
        status="trusted",
    ),
)
