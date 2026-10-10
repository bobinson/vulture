from django.http import HttpResponse

from .runtime import is_auth_disabled


def require_login(view):
    def wrapped(request, *args, **kwargs):
        if request.headers.get("X-Skip") == "1" and is_auth_disabled():
            return view(request, *args, **kwargs)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *args, **kwargs)
    return wrapped
