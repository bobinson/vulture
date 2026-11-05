from flask import abort, request, session

from .stores import legacy_user_store, user_store


def load_user_for_request():
    if request.headers.get("X-Tenant") == "legacy":
        return legacy_user_store.get_user(session["uid"])
    if "uid" not in session:
        abort(401)
    return user_store.get_user(session["uid"])
