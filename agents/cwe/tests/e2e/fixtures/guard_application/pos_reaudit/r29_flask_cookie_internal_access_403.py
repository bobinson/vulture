from flask import abort, request


def require_staff(view):
    def wrapped(*args, **kwargs):
        if request.cookies.get("internal_access") == "1":
            return view(*args, **kwargs)
        abort(403)
    return wrapped
