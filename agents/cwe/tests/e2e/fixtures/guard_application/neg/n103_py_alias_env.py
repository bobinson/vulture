import os

from flask import abort, request
from flask_login import current_user

from .app import app


@app.before_request
def guard():
    trusted = request.headers.get("X-Service-Key") == os.environ["SERVICE_KEY"]
    if trusted:
        return
    if not current_user.is_authenticated:
        abort(401)
