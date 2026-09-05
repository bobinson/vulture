"""DISCOVER tier — endpoint suggestion. Feature 0089 Phase 0.c.

Transcribed from `discover_agent/plugins/llm_suggest.py:_LLM_DISCOVER_PROMPT`
byte for byte. The whole prompt goes in `user_fragments`: the call site builds
`messages=[{"role": "user", ...}]` and sets no system message at all
(`llm_suggest.py:110-121`), so `fragments` is empty by transcription, not by
omission.

Three lint findings are EXPECTED here and are the audit record this phase is
for (Phase 4.6 owns the fixes; changing the text here would erase the before):

- `exemplar_validity` — the one worked example is `{"endpoints": ["/api/path1",
  "/api/path2", ...], "reasoning": "..."}`, whose bare `...` makes it invalid
  JSON. The plugin's own reader is a hard `json.loads`, so a model that copies
  the shape it was shown loses the entire suggestion round.
- `placeholder_echo` — the same `...`, seen as a literal a model may emit.
- `language_pin` — `reasoning` is free text that egresses with no bound
  output language.

A fourth finding is recorded here that promptlint CANNOT see: `{technologies}`,
`{forms}` and `{headers}` are filled from the scanned site's own response
headers and HTML (`llm_suggest.py:84-104`) and are spliced in with no
delimiter and no MARKS_UNTRUSTED fragment. `check_05_slot_marking` only fires
for a spec that declares `slots`, and a transcription must declare none —
wrapping a slot changes the rendered bytes. Phase 2 turns these into real
slots; until then the gap is pinned by
`test_discover_interpolates_target_bytes_with_no_untrusted_marker`.
"""

from __future__ import annotations

from ..backlog import LANGUAGE_PIN, OWNER
from ..lint import LintAllow
from ..spec import PromptSpec

DISCOVER_SUGGEST = PromptSpec(
    id="discover_suggest",
    tier="discover",
    fragments=(),
    user_fragments=("discover/suggest",),
    schema_fields=("endpoints", "reasoning"),
    # The three findings this module's docstring records as EXPECTED, now
    # annotated so the Phase 3 gate admits them without silencing the check.
    allow=(
        LintAllow("language_pin", "discover_suggest", owner=OWNER,
                  reason=LANGUAGE_PIN),
        LintAllow(
            "exemplar_validity", "discover/suggest", owner=OWNER,
            reason="Phase 4.6 — the one worked example is invalid JSON (a bare "
                   "`...` inside the endpoints array), and the plugin's reader "
                   "is a hard `json.loads`, so a model that copies the shape it "
                   "was shown loses the entire suggestion round.",
        ),
        LintAllow(
            "placeholder_echo", "discover/suggest", owner=OWNER,
            reason="Phase 4.6 — the same bare `...`, seen by `check_09` as a "
                   "literal the model may emit rather than as elision. Same "
                   "line and same fix as the `exemplar_validity` entry above; "
                   "kept separate because the two checks would be satisfied by "
                   "different repairs (valid JSON vs. no echoable placeholder).",
        ),
    ),
)
