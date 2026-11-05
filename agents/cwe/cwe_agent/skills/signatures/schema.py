"""P4a — the ``CweSignature`` declarative schema (feature 0057 Phase 4).

A signature is a *declarative sink/source/sanitizer rule* (R10) with a
bounded line window. The executor (``detector.match_signatures``) is one
generic 3-step matcher; signatures themselves are pure data — compiled-regex
``.py`` modules, NOT JSON, mirroring the ``injection_check.py`` convention of
module-level ``re.compile`` constants (DRY).

Tiering (R13 / P4e): every shipped signature lands as ``status="candidate"``
until its CWE passes the Phase-5 corpus gate, which promotes it to
``trusted``. Only a ``trusted`` signature gets the voter's 2-demoting-check
floor; a ``candidate`` is L5-demotable like an LLM finding.

ReDoS-safety invariant: all regex carried by a signature MUST use bounded
quantifiers / length caps. The matcher additionally length-caps every line
before matching, so even a hostile source line cannot trigger catastrophic
backtracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CweSignature:
    """One deterministic sink/source/sanitizer signature.

    Attributes:
        cwe_id: Numeric CWE id string, e.g. ``"1333"`` (becomes ``category =
            CWE-<cwe_id>``).
        sig_id: Stable signature id, e.g. ``"cwe.sig.redos"`` (becomes the
            finding ``check_id`` — the dedup key component, R11).
        title: Human-readable finding title.
        severity: One of ``critical|high|medium|low``.
        languages: Catalog language names this signature applies to
            (e.g. ``("JavaScript", "TypeScript")``); mapped to file
            extensions by the detector's ext index.
        sink: Compiled, ReDoS-safe regex that gates a candidate line.
        source: Optional compiled regex for a tainted source; required to
            be present within ``±window`` lines when ``require_source``.
        sanitizer: Optional compiled regex; a match within ``±window``
            lines suppresses the finding.
        window: Half-window (in lines) for source/sanitizer search.
        confidence: Detector confidence in ``[0, 1]``.
        require_source: When True, a ``source`` match within the window is
            mandatory for the signature to fire (dataflow gate).
        source_flows: With ``require_source``, the source must reach the
            sink line instead of merely appearing near it: the line's code
            (string text blanked, interpolations kept) matches ``source``, or
            names a variable that a line up to ``window`` above assigns from
            a ``source`` match. A source word elsewhere does not count.
        status: ``candidate`` (default; not yet corpus-gated) or ``trusted``.
    """

    cwe_id: str
    sig_id: str
    title: str
    severity: str
    languages: tuple[str, ...]
    sink: re.Pattern
    source: re.Pattern | None = None
    sanitizer: re.Pattern | None = None
    window: int = 4
    confidence: float = 0.6
    require_source: bool = False
    source_flows: bool = False
    status: str = "candidate"
