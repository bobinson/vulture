from flask import abort, request

from .app import app

try:
    from local_settings import INTERNAL_TOKEN
except ImportError:
    INTERNAL_TOKEN = "dev-only"


@app.before_request
def internal():
    if request.headers.get("X-Internal-Token") == INTERNAL_TOKEN:
        return
    abort(401)
