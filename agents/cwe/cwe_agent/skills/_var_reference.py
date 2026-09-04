"""Re-export shim. The implementation moved to ``shared.tools.var_reference``.

Feature 0079 B2. Variable-indirection detection is not CWE-specific -- ASVS and
SSDF both scan for credential-shaped strings and both benefit from knowing that
``password = $DB_PASS`` is a reference, not a secret. ``file_scanner.py`` already
documented the file as living at ``shared/tools/_var_reference.py``, so shared
had anticipated the move before it happened.

Kept as a shim rather than a rename so the four CWE call sites and three CWE
test modules are untouched, which is what makes the move provably
behaviour-preserving.
"""

from shared.tools.var_reference import (  # noqa: F401
    _RHS_CAPTURE,
    _VAR_REF_RE,
    is_variable_reference,
    line_value_is_variable_ref,
)

__all__ = [
    "is_variable_reference",
    "line_value_is_variable_ref",
    "_VAR_REF_RE",
    "_RHS_CAPTURE",
]
