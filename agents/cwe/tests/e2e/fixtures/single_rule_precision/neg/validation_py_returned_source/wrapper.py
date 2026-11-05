"""A JSON endpoint whose reader returns the parsed body to its one caller."""
import email.message
from typing import Any


class HTTPError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status


def _is_json_media_type(content_type: str) -> bool:
    message = email.message.Message()
    message["content-type"] = content_type
    return message.get_content_maintype() == "application"


async def _read_json(req) -> Any:
    try:
        # EXPECT-NEXT: clean
        return await req.json()
    except ValueError as exc:
        raise HTTPError(400, "invalid JSON body") from exc


async def run(req):
    body: Any = await _read_json(req)
    _validate_envelope(body)  # noqa: F821 -- read as text
    run_id = body.get("run_id", "")
    return run_id
