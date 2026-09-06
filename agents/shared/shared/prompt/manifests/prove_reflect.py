"""PROVE reflect manifests — feature 0089 Phase 0.c (transcribe).

Five per-strategy reflection prompts, kept as separate specs (they diverge in
domain wording). Each emits the same four-field contract, including an
`analysis` free-text field. That field is compatible with `prove/system`'s
FORBIDS_PROSE stance, which Item 4.5 clarified to be envelope-scoped (strict
JSON, no prose around the object) — free-text values inside the object's
fields are exactly what the contract asks for.

Item 4.8 added `core/language` to the system turn. These five specs carried no
`language_pin` annotation to retire — `check_12`'s free-text field set is
`reasoning`/`description`/`title`/`recommendation`/`evidence`, and this schema
names none of them, so the check never fired here even though `analysis`,
`suggested_approach` and `learnings` are exactly as free and egress exactly as
far. They list the clause anyway, for two reasons: the drift it prevents does
not care which field name the schema chose, and their `fragments` tuple IS the
system turn `llm_helper` sends, so a spec that omitted it would be describing a
turn production does not send.
"""

from __future__ import annotations

from ..spec import PromptSpec

_REFLECT_SCHEMA = ("analysis", "suggested_approach", "confidence", "learnings")

_STRATEGIES = ("cwe", "owasp", "soc2", "ssdf", "chaos")

PROVE_REFLECT: dict[str, PromptSpec] = {
    name: PromptSpec(
        id=f"prove_reflect_{name}",
        tier="prove",
        version=3,  # 4.5: shared prove/system reworded. 4.8: core/language
        fragments=("prove/system", "core/language"),
        user_fragments=(f"prove/reflect_{name}",),
        schema_fields=_REFLECT_SCHEMA,
    )
    for name in _STRATEGIES
}

# Bind each spec to a module-level name so the auto-discovering MANIFESTS
# loader (which scans top-level PromptSpec values, not dict members) finds it.
for _name, _spec in PROVE_REFLECT.items():
    globals()[f"PROVE_REFLECT_{_name.upper()}"] = _spec


# ── Phase 2.6: the collapsed single-template family ───────────────────────
#
# As for plan: the five `prove/reflect_{name}` fragments and `PROVE_REFLECT`
# specs above stay as the byte-pinned oracle (golden + lint citizens), and the
# runtime collapses onto one `prove/reflect` template rendered with the
# per-strategy slot values below via `render_prove_prompt`. reflect diverges in
# only two spans — the persona line and the middle three "Analyze:" items
# (points 2-4); points 1 and 5 are constant across all five, so they stay in the
# skeleton. `prove/reflect` is not its own manifest spec, for the reason spelled
# out in `prove_plan.py`; `test_0089_parity_prove_collapse.py` pins it byte for
# byte against each strategy's shipped `_REFLECT_PROMPT`.

PROVE_REFLECT_DOMAIN: dict[str, dict[str, str]] = {
    "cwe": {
        "persona": "You are a vulnerability researcher reflecting on failed verification attempts.",
        "domain_rules": "\n".join((
            "2. What does the target's behavior reveal about its defenses or architecture?",
            "3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different technique)",
            "4. How confident are you (0-100) that this vulnerability actually exists on the target?",
        )),
    },
    "owasp": {
        "persona": "You are a security researcher reflecting on failed verification attempts.",
        "domain_rules": "\n".join((
            "2. What does the target's behavior reveal about its architecture/defenses?",
            "3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different technique)",
            "4. How confident are you (0-100) that this vulnerability actually exists on the target?",
        )),
    },
    "soc2": {
        "persona": "You are a SOC2 compliance auditor reflecting on failed verification attempts.",
        "domain_rules": "\n".join((
            "2. What does the target's behavior reveal about its compliance posture?",
            "3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different check)",
            "4. How confident are you (0-100) that this compliance gap actually exists on the target?",
        )),
    },
    "ssdf": {
        "persona": "You are a NIST SSDF v1.1 compliance auditor reflecting on failed verification attempts.",
        "domain_rules": "\n".join((
            "2. What does the target's behavior reveal about its SSDF compliance posture?",
            "3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different check)",
            "4. How confident are you (0-100) that this compliance gap actually exists on the target?",
        )),
    },
    "chaos": {
        "persona": "You are a resilience engineer reflecting on failed verification attempts.",
        "domain_rules": "\n".join((
            "2. What does the target's behavior reveal about its resilience patterns?",
            "3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different technique)",
            "4. How confident are you (0-100) that this resilience gap actually exists on the target?",
        )),
    },
}
