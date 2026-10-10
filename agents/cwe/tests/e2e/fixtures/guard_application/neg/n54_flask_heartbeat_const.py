import os

from flask import redirect, request, url_for
from flask_login import current_user

from .app import app

HEARTBEAT_TOKEN = os.environ["HEARTBEAT_TOKEN"]


@app.before_request
def guard():
    if request.headers.get("X-Heartbeat-Token") == HEARTBEAT_TOKEN:
        return
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
