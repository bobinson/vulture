"""PROVE plan manifests — feature 0089 Phase 0.c (transcribe).

Five per-strategy plan prompts, kept as separate specs. They are 66-75%
similar; Phase 2.6 will collapse them. Unifying now would break Phase 1 parity,
so this phase transcribes each byte-for-byte.

`schema_fields` is the real ProofPlan contract each exemplar emits. cwe's plan
additionally instructs the model to emit `filename` (rule 8, file upload),
which no schema has — declared on the fragment so promptlint reports it as an
`orphan_field` ("unfielded instruction").
"""

from __future__ import annotations

from ..backlog import LANGUAGE_PIN, OWNER
from ..lint import LintAllow
from ..spec import PromptSpec

_PLAN_SCHEMA = ("description", "method", "url_path", "headers", "body",
                "expected_indicators")

_STRATEGIES = ("cwe", "owasp", "soc2", "ssdf", "chaos")

# The one exemption in this file that is a true positive of exactly the class
# `check_09` is named for: the executor SENDS `url_path`, so an exemplar that
# teaches `/real-path` teaches a request to a path that does not exist.
_ECHO_REASON = (
    "Phase 4.5 — the plan exemplar teaches `url_path: \"/real-path\"` (and, on "
    "cwe, `body: \"payload if POST\"`), and the prove executor sends `url_path` "
    "as a real HTTP request, so a model that copies the exemplar probes a path "
    "that does not exist. This is the defect class `check_09` is named for, "
    "not a reporting artefact."
)


def _plan_allow(name: str) -> tuple[LintAllow, ...]:
    return (
        LintAllow("language_pin", f"prove_plan_{name}", owner=OWNER,
                  reason=LANGUAGE_PIN),
        LintAllow("placeholder_echo", f"prove/plan_{name}", owner=OWNER,
                  reason=_ECHO_REASON),
    )


# cwe's plan alone instructs the model to emit `filename` (rule 8, file
# upload), which `_PLAN_SCHEMA` does not have.
_CWE_ALLOW: tuple[LintAllow, ...] = (
    LintAllow(
        "orphan_field", "prove/plan_cwe", owner=OWNER,
        reason="Phase 4.5 — `prove/plan_cwe` instructs the model to emit "
               "`filename`, which is not in `_PLAN_SCHEMA`, so the field is "
               "dropped on parse and the file-upload probe it describes cannot "
               "be built. 4.5 either adds the field to the ProofPlan contract "
               "or removes the instruction.",
    ),
)

PROVE_PLANS: dict[str, PromptSpec] = {
    name: PromptSpec(
        id=f"prove_plan_{name}",
        tier="prove",
        fragments=("prove/system",),
        user_fragments=(f"prove/plan_{name}",),
        schema_fields=_PLAN_SCHEMA,
        allow=_plan_allow(name) + (_CWE_ALLOW if name == "cwe" else ()),
    )
    for name in _STRATEGIES
}

# Bind each spec to a module-level name so the auto-discovering MANIFESTS
# loader (which scans top-level PromptSpec values, not dict members) finds it.
for _name, _spec in PROVE_PLANS.items():
    globals()[f"PROVE_PLAN_{_name.upper()}"] = _spec


# ── Phase 2.6: the collapsed single-template family ───────────────────────
#
# The five per-strategy `prove/plan_{name}` fragments and `PROVE_PLANS` specs
# above are 66-75% identical copies; they STAY as the transcription oracle,
# byte-pinned to the live `_PLAN_PROMPT` constants by `test_0089_parity_prove*`
# and the golden gate, and they are the carrier of cwe's `filename` orphan_field
# — a per-fragment lint finding that cannot live on a shared template without
# firing for the four strategies that do not want it. They remain this family's
# golden/lint citizens.
#
# The RUNTIME collapses onto ONE template. `prove/plan` is cwe's text with its
# varying spans lifted into placeholders; every strategy's `plan()` renders it
# with the slot values below via `render_prove_prompt` (`prove_agent/
# llm_helper.py`), naming the fragment `"prove/plan"` — see `strategies/*.py`.
#
# `prove/plan` is deliberately NOT its own manifest spec: the per-strategy specs
# already carry this family's golden + lint coverage, and a second manifest would
# only duplicate their `/real-path` placeholder_echo and language_pin backlog
# entries under a new id (raising the Phase-3 allow ceiling for no new coverage).
# The collapsed template is pinned instead — more strongly than a self-
# referential golden — by `test_0089_parity_prove_collapse.py`, which renders it
# with each strategy's slots and asserts byte equality against that strategy's
# shipped `_PLAN_PROMPT`.
#
# Slots: the task named three — `{persona}`, `{domain_rules}`, `{evidence_block}`
# — but byte parity needs a fourth. The JSON `body` exemplar value also varies
# (cwe alone teaches "payload if POST"; the other four are empty) and it sits in
# the contract tail, outside all three named spans, so `{body_example}` is a
# fourth slot, not a wording change.

# Per-strategy values that fill `prove/plan`'s four slots. Merged with the
# per-call runtime variables (title, category, …) at the call site; render's
# `_fill` is a plain replace, so a runtime `{code_snippet}` inside a filled
# `evidence_block` is resolved in the same pass (domain keys are inserted
# first). cwe/owasp carry the Code/Hints evidence block; soc2/ssdf/chaos do
# not, so their `evidence_block` is empty and the JSON `body` example likewise.
PROVE_PLAN_DOMAIN: dict[str, dict[str, str]] = {
    "cwe": {
        "persona": "You are a vulnerability researcher. Given this CWE finding, create an HTTP request to verify the vulnerability on the staging server.",
        "domain_rules": "\n".join((
            '2. Do NOT use "/" as the url_path — pick a specific endpoint.',
            "3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.",
            "4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.",
            "5. Each attempt MUST target a DIFFERENT endpoint or use a different payload.",
            "6. For injection: craft payloads specific to the CWE type (SQL, XSS, command, path traversal).",
            "7. For hardcoded credentials: check config endpoints and API responses (NOT .js files).",
            "8. For file upload: target upload endpoints with malicious filenames.",
        )),
        "evidence_block": "Code: {code_snippet}\nHints: {verification_hints}\n",
        "body_example": "payload if POST",
    },
    "owasp": {
        "persona": "You are a security tester. Given this OWASP finding, create an HTTP request to verify it against a staging server.",
        "domain_rules": "\n".join((
            '2. Do NOT use "/" as the url_path — pick a specific page, API endpoint, or form action.',
            "3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.",
            "4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and authentication endpoints.",
            "5. Each attempt MUST target a DIFFERENT endpoint or use a different technique.",
            "6. For injection flaws: craft actual payloads (SQL injection, XSS, etc.) in the body or query string.",
            "7. For auth issues: try accessing protected pages without credentials, or with weak/default ones.",
            "8. For crypto/secrets: check config endpoints, response headers for leaked data.",
        )),
        "evidence_block": "Code: {code_snippet}\nHints: {verification_hints}\n",
        "body_example": "",
    },
    "soc2": {
        "persona": "You are a SOC2 compliance auditor. Given this SOC2 finding, create an HTTP request to verify the compliance gap on the staging server.",
        "domain_rules": "\n".join((
            '2. Do NOT use "/" as the url_path — pick a specific endpoint.',
            "3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.",
            "4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.",
            "5. Each attempt MUST target a DIFFERENT endpoint or check a different aspect.",
            "6. For encryption: check response headers (HSTS, TLS version, cookie flags).",
            "7. For access control: try accessing protected pages without auth.",
            "8. For config exposure: check settings pages, env endpoints, health checks.",
        )),
        "evidence_block": "",
        "body_example": "",
    },
    "ssdf": {
        "persona": "You are a NIST SSDF v1.1 compliance auditor. Given this SSDF finding, create an HTTP request to verify the compliance gap on the staging server.",
        "domain_rules": "\n".join((
            '2. Do NOT use "/" as the url_path — pick a specific endpoint.',
            "3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files).",
            "4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.",
            "5. Each attempt MUST target a DIFFERENT endpoint or check a different aspect.",
            "6. For PO.5/PW.9: check response headers (HSTS, CSP, X-Frame-Options), probe debug endpoints.",
            "7. For PS.1: check for exposed .git/ directory, source maps.",
            "8. For PW.6: check Server header for version disclosure, check TLS config.",
            "9. For PW.9: probe default credentials, debug endpoints (/debug/, /admin/).",
            "10. For PO.1/PS.2: check for /.well-known/security.txt, /security.txt.",
        )),
        "evidence_block": "",
        "body_example": "",
    },
    "chaos": {
        "persona": "You are a resilience tester. Given this chaos engineering finding, create an HTTP request to verify missing resilience patterns on the staging server.",
        "domain_rules": "\n".join((
            '2. Do NOT use "/" as the url_path — pick a specific endpoint.',
            "3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.",
            "4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.",
            "5. Each attempt MUST target a DIFFERENT endpoint or use a different technique.",
            "6. For timeout issues: send requests with large payloads or slow headers.",
            "7. For missing retries: target endpoints that call external services.",
            "8. For missing fallbacks: test degraded mode behavior.",
        )),
        "evidence_block": "",
        "body_example": "",
    },
}
