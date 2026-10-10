from flask import abort, request

from .app import app

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


@app.before_request
def csrf_protect():
    if request.method in SAFE_METHODS:
        return
    if request.headers.get("X-CSRFToken") == request.cookies.get("csrftoken"):
        return
    abort(403)
