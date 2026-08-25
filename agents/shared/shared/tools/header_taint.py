"""HTTP header name + tainted value, anchored at BOTH ends.

Two agents wrote the same pattern and both wrote it unanchored:

    re.compile(r"Location.*(?:request|req|params|query|user|input)", re.IGNORECASE)

appears in ``xss_agent/skills/header_injection_check.py`` (CWE-113) and in
``cwe_agent/skills/web_security_check.py`` (CWE-601). Neither end is anchored,
so ordinary code matches::

    const hasProfileLocation = Boolean(userAddressData);
    #          ^^^^^^^^ "Location"        ^^^^ "user"

"Location" is a substring of ``hasProfileLocation`` and "user" of
``userAddressData``, and IGNORECASE makes both reachable. Measured on a real
target, this produced a CWE-113 "HTTP header injection via user input" finding
on a line that sets no header and contains no user input.

The fix is anchoring, not narrowing: a header name counts only when it appears
AS a header -- quoted (``"Location"``) or followed by a colon (``Location:``) --
and a taint token counts only as a whole word, so ``userAddressData`` no longer
qualifies while ``req.query.next`` still does.
"""
from __future__ import annotations

import re

# Whole-word taint markers. `req` is included as a word so `req.query` matches
# while `request_id_prefix` does not contribute on its own.
TAINT_WORD = r"\b(?:request|req|params|param|query|body|input|user|argv)\b"


def header_taint_pattern(header: str, *, taint: str = TAINT_WORD) -> re.Pattern[str]:
    """Pattern matching ``header`` used AS a header alongside a tainted value.

    ``header`` is matched quoted or colon-terminated, never as a bare identifier
    fragment. The gap between the two is bounded (no nested quantifier), so this
    is ReDoS-safe.
    """
    name = re.escape(header)
    return re.compile(
        rf"""(?:['"`]{name}['"`]|\b{name}\s*:)"""
        rf"""[^\n]{{0,200}}?{taint}""",
        re.IGNORECASE,
    )
