from flask import abort, request

from .mail import send_message_email


def send_secret_message():
    if not check_secret_message(request):
        abort(400)
    to = request.form["to"]
    send_message_email(to, request.form["message"])
    return "", 204
