from flask import abort, request

from .mail import send_welcome_email
from .security import verify_webhook_secret


def on_signup():
    trusted = verify_webhook_secret(request.headers)
    if not trusted:
        abort(403)
    email = request.json["email"]
    send_welcome_email(email)
    return "", 204
