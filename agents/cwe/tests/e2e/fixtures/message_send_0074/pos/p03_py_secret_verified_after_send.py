from flask import request

from .mail import send_magic_link_email
from .security import verify_webhook_secret


def start():
    email = request.json["email"]
    send_magic_link_email(email)
    verify_webhook_secret(request.headers)
    return "", 204
