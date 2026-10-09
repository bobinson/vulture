import os

from flask import abort, request

from .app import app

SHARED_SECRET = "dev"
if os.environ.get("SHARED_SECRET"): SHARED_SECRET = os.environ["SHARED_SECRET"]  # noqa: E701


@app.before_request
def guard():
    if request.headers.get("X-Shared-Key") == SHARED_SECRET:
        return
    abort(401)
