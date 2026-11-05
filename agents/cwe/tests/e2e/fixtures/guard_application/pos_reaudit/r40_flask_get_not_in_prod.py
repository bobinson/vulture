from flask import abort, request
from flask_login import current_user

from .app import app


@app.before_request
def guard():
    if request.headers.get("X-Env") not in ("prod", "production"):
        return
    if not current_user.is_authenticated:
        abort(401)
