"""Shared promptlint exemption text. Feature 0089 Phase 3.

Deliberately OUTSIDE `manifests/`: every module in that package must define a
module-level `PromptSpec` (the registry harvests them, and
`test_every_manifest_module_reaches_the_registry` fails a module that defines
none, precisely so a manifest cannot go missing from the golden gate and the
lint sweep at once). A constants module has no spec to offer, so it lives here.

It existed for one constant, `LANGUAGE_PIN`, and item 4.8 retired it. That
entry read the same on every tier — no fragment in the library carried
`BINDS_LANGUAGE`, so `check_12_language_pin` fired on eighteen specs at once —
and transcribing one reason into five manifests would have been five places it
could drift from the fix. `core/language` is that fix, so the constant is gone
rather than left behind describing a defect that no longer exists; that is the
`allow_stale` rule (`lint.gate`) applied to the reason text as well as to the
entries.

`OWNER` stays. Two exemptions still stand — `duplicate_contract` and
`orphan_field` on the `domains/` fragments of cwe and asvs, plus the judge's
`exemplar_validity` — and each names its own tier-specific reason next to the
fragment list it excuses, which is where a reason that is NOT shared belongs.
"""

from __future__ import annotations

OWNER = "bobinson"
