"""PROVE analyze manifests — feature 0089 Phase 0.c (transcribe).

Three protocol variants (HTTP, WebSocket, JSON-RPC) that ask the model to judge
whether a probe response confirmed the vulnerability. Each interpolates a raw,
untrusted response body. Item 4.5 moved that body to the END of the prompt,
with the output contract and an undecidable clause ("set conclusive to false"
when the response does not decide it) placed ABOVE it, so no interpolated
response can sit after an instruction. The body is still not wrapped in a Slot
(no MARKS_UNTRUSTED stance yet); that stronger guard is a later phase, and with
slots empty promptlint's slot_marking check stays silent until then.
"""

from __future__ import annotations

from ..spec import PromptSpec

_ANALYZE_SCHEMA = ("conclusive", "reproduced", "evidence")

_PROTOCOLS = ("http", "ws", "jsonrpc")

PROVE_ANALYZE: dict[str, PromptSpec] = {
    proto: PromptSpec(
        id=f"prove_analyze_{proto}",
        tier="prove",
        version=3,  # 4.5: prove/system reworded. 4.8: core/language
        # `evidence` is free text that egresses; item 4.8 binds its language
        # with `core/language` and retires the `language_pin` entry that stood
        # here. The untrusted-body gap named in the docstring above is a
        # different, still-open finding: promptlint cannot see it while `slots`
        # is empty, and it is pinned by the prove parity tests instead.
        fragments=("prove/system", "core/language"),
        user_fragments=(f"prove/analyze_{proto}",),
        schema_fields=_ANALYZE_SCHEMA,
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
