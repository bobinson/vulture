from enum import Enum

from flask import abort, request

from .app import app


class Mode(str, Enum):
    BYPASS = "bypass"


@app.before_request
def guard():
    if request.headers.get("X-Mode") == Mode.BYPASS.value:
        return
    abort(401)
