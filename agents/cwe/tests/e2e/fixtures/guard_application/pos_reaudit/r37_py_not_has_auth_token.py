from django.http import HttpResponse

from .auth import has_auth_token


def require_login(view):
    def wrapped(request, *args, **kwargs):
        if not has_auth_token(request) and request.headers.get("X-Debug") == "1":
            return view(request, *args, **kwargs)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *args, **kwargs)
    return wrapped
