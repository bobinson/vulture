"""The fixture must come from the SDK, not from our idea of the SDK.

`_broker_detail` was written against `{"error": {...}}` — the shape the broker
puts on the wire (`broker/server/dto.go::writeErr`). The openai SDK does NOT
hand that to the exception: `_make_status_error` does

    data = body.get("error", body) if is_mapping(body) else body

and passes the INNER object as `body=`. So `body.get("error")` was None on every
real broker error and the function returned "" — the whole pass-through was
dead code on the production path, while 13 unit tests passed because their
helper fabricated the wrapped shape.

These tests drive a real `openai.OpenAI` client against a stub that speaks the
broker's exact envelope, so the fixture cannot drift from the SDK again.
"""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from shared.validate import llm_judge

BROKER_404 = {
    "error": {
        "message": "model not found or not routable",
        "type": "model_not_found",
        "code": "model_not_found",
        "x_retriable": False,
        "upstream": {
            "provider": "gemini",
            "status": 404,
            "message": "models/gemini-pro is not found for API version v1beta. Call ModelService.ListModels",
        },
    }
}

# A DIRECT provider error has the same UNWRAPPED shape once the SDK is done with
# it, and carries no `x_retriable`. It must not be reported as "broker says".
PROVIDER_404 = {
    "error": {
        "message": "The model `gpt-4o-xyz` does not exist",
        "type": "invalid_request_error",
        "code": "model_not_found",
    }
}


def _serve(payload: dict, status: int):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            b = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _raise_via_sdk(payload: dict, status: int) -> Exception:
    """Return the exception the REAL SDK raises for this response."""
    openai = pytest.importorskip("openai")
    srv = _serve(payload, status)
    try:
        client = openai.OpenAI(base_url=f"http://127.0.0.1:{srv.server_address[1]}/v1",
                               api_key="test", max_retries=0)
        with pytest.raises(Exception) as ei:
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        return ei.value
    finally:
        srv.shutdown()


def test_broker_envelope_survives_the_real_sdk(caplog):
    exc = _raise_via_sdk(BROKER_404, 502)
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(exc, "tool-loop")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "model_not_found" in text, f"the broker's code must survive the SDK unwrap; got {text!r}"
    assert "gemini-pro" in text, f"the provider's own message must reach the operator; got {text!r}"
    assert "ListModels" in text


def test_a_direct_provider_error_is_not_attributed_to_the_broker(caplog):
    """Same unwrapped shape, no broker marker. Claiming 'broker says' here would
    be confidently wrong, and would re-admit provider text on a path the broker
    deliberately gates to 404/409."""
    exc = _raise_via_sdk(PROVIDER_404, 404)
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(exc, "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "broker says" not in text, (
        f"a direct provider error must not be reported as the broker's verdict; got {text!r}"
    )
    assert "could not reach the LLM endpoint" in text, "it keeps the generic diagnosis"


def test_the_sdk_really_does_unwrap():
    """Pin the SDK behaviour this module exists to accommodate, so an SDK
    upgrade that changes it fails here loudly rather than silently."""
    exc = _raise_via_sdk(BROKER_404, 502)
    body = getattr(exc, "body", None)
    assert isinstance(body, dict)
    assert "error" not in body, (
        "the SDK stopped unwrapping; _broker_detail's dual-shape handling may now be "
        f"over-permissive. body keys = {sorted(body)}"
    )
    assert body.get("code") == "model_not_found"
