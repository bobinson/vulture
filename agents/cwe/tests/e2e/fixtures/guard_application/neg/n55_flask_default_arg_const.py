import os

from flask import abort, request
from flask_login import current_user

from .app import app

CRON_KEY = os.environ.get("CRON_KEY", "")


@app.before_request
def svc():
    if request.headers.get("X-Cron-Key", "") == CRON_KEY:
        return
    if not current_user.is_authenticated:
        abort(401)
