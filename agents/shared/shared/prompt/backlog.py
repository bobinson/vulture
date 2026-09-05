"""Shared promptlint exemption text. Feature 0089 Phase 3.

Deliberately OUTSIDE `manifests/`: every module in that package must define a
module-level `PromptSpec` (the registry harvests them, and
`test_every_manifest_module_reaches_the_registry` fails a module that defines
none, precisely so a manifest cannot go missing from the golden gate and the
lint sweep at once). A constants module has no spec to offer, so it lives here.

It exists because `language_pin` fires on every tier for one reason — no
fragment in the library carries `BINDS_LANGUAGE` at all — and a reason
transcribed into five manifests is five places it can drift from the fix that
eventually lands. Tier-specific reasons stay in their own manifest, next to the
fragment list they excuse.
"""

from __future__ import annotations

OWNER = "bobinson"

# Every spec with a free-text schema field trips this, in all six tiers.
LANGUAGE_PIN = (
    "Phase 4.8 — no fragment in the library carries BINDS_LANGUAGE, so every "
    "free-text field egresses with no bound output language. 4.8 adds "
    "`core/language`, admitted by `render._rule_language` only where the "
    "profile's `output_language_pin` is set (4 of the 10 families)."
)
