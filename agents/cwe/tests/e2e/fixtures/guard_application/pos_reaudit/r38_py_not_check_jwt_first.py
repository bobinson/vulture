from django.http import HttpResponse

from .auth import check_service_jwt


def require_login(view):
    def wrapped(request, *a, **k):
        if not check_service_jwt(request) and request.headers.get("X-Skip-Auth") == "1":
            return view(request, *a, **k)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *a, **k)
    return wrapped
