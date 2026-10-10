from functools import wraps

from flask import abort, request

TRUSTED_NETWORKS = {"10.0.0.5", "127.0.0.1"}


def internal_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if client_ip in TRUSTED_NETWORKS:
            return view(*args, **kwargs)
        abort(403)
    return wrapper
