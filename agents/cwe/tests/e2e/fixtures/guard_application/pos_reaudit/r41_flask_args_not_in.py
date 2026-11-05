from flask import abort, request
from flask_login import current_user

from .app import app

PROD_MODES = ("prod", "production")


@app.before_request
def guard():
    if request.args.get("mode") not in PROD_MODES:
        return
    if not current_user.is_authenticated:
        abort(401)
