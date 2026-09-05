"""PROVE analyze manifests — feature 0089 Phase 0.c (transcribe).

Three protocol variants (HTTP, WebSocket, JSON-RPC) that ask the model to judge
whether a probe response confirmed the vulnerability. Each interpolates a raw,
untrusted response body — and NONE of them marks it as untrusted. That gap is
deliberately preserved here (no MARKS_UNTRUSTED stance on the fragments); it is
the audit finding. Slots are empty at this phase, so promptlint's slot_marking
check stays silent until the interpolation moves onto a Slot in a later phase.
"""

from __future__ import annotations

from ..backlog import LANGUAGE_PIN, OWNER
from ..lint import LintAllow
from ..spec import PromptSpec

_ANALYZE_SCHEMA = ("conclusive", "reproduced", "evidence")

_PROTOCOLS = ("http", "ws", "jsonrpc")

PROVE_ANALYZE: dict[str, PromptSpec] = {
    proto: PromptSpec(
        id=f"prove_analyze_{proto}",
        tier="prove",
        fragments=("prove/system",),
        user_fragments=(f"prove/analyze_{proto}",),
        schema_fields=_ANALYZE_SCHEMA,
        # `evidence` is free text that egresses. The untrusted-body gap named
        # in the docstring above is NOT here: promptlint cannot see it while
        # `slots` is empty, and it is pinned by the prove parity tests instead.
        allow=(LintAllow("language_pin", f"prove_analyze_{proto}",
                         owner=OWNER, reason=LANGUAGE_PIN),),
    )
    for proto in _PROTOCOLS
}

# Bind each spec to a module-level name so the auto-discovering MANIFESTS
# loader (which scans top-level PromptSpec values, not dict members) finds it.
for _proto, _spec in PROVE_ANALYZE.items():
    globals()[f"PROVE_ANALYZE_{_proto.upper()}"] = _spec


# ── Phase 2.6: the collapsed single-template family ───────────────────────
#
# The three `prove/analyze_{proto}` fragments and `PROVE_ANALYZE` specs above
# stay as the byte-pinned oracle (golden + lint citizens); the runtime collapses
# onto one `prove/analyze` template rendered with the per-protocol slot values
# below via `render_prove_prompt`. analyze diverges in only two spans — the
# protocol name in the opening question, and the request/response detail lines
# between the finding line and the "Expected indicators" line. `prove/analyze`
# is not its own manifest spec, for the reason spelled out in `prove_plan.py`;
# `test_0089_parity_prove_collapse.py` pins it byte for byte against each
# protocol's shipped `_ANALYZE_PROMPT`.

PROVE_ANALYZE_DOMAIN: dict[str, dict[str, str]] = {
    "http": {
        "protocol": "HTTP",
        "request_block": "\n".join((
            "Request: {method} {url}",
            "Status: {status_code}",
            "Response headers: {response_headers}",
            "Response (truncated): {response_snippet}",
        )),
    },
    "ws": {
        "protocol": "WebSocket",
        "request_block": "\n".join((
            "Request: WebSocket message to {url}",
            "Messages received: {messages}",
        )),
    },
    "jsonrpc": {
        "protocol": "JSON-RPC",
        "request_block": "\n".join((
            "RPC method: {method}",
            "Response: {response}",
        )),
    },
}
