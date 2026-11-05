from flask import abort, request

from .app import app


@app.before_request
def auth():
    if "X-Internal" not in request.headers:
        abort(401)
