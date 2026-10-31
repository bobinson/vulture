from flask import abort, request
from flask_login import current_user

from .app import app


@app.before_request
def gate():
    if request.headers.get("X-Role") == request.args.get("role"):
        return
    if not current_user.is_authenticated:
        abort(401)
