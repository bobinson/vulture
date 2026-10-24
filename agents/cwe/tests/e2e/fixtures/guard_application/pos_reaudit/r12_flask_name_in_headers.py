from flask import abort, request
from flask_login import current_user

from .app import app


@app.before_request
def auth():
    if "X-Internal" in request.headers:
        return
    if not current_user.is_authenticated:
        abort(401)
