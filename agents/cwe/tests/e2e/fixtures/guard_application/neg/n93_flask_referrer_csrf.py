from flask import abort, request

from .app import app


@app.before_request
def csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.referrer and request.referrer.startswith(request.host_url):
        return
    abort(403)
