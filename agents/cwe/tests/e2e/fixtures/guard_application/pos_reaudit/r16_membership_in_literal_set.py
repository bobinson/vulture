from flask import abort, request

from .app import app

ALLOWED_SERVICES = {"billing", "search"}


@app.before_request
def svc():
    if request.headers.get("X-Service-Name") in ALLOWED_SERVICES:
        return
    abort(401)
