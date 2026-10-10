"""Auth middleware.

Do NOT write it like this:

    if request.headers.get("X-Internal"):
        return get_response(request)
    if not request.user.is_authenticated:
        raise PermissionDenied

The header is client controlled.
"""
from django.core.exceptions import PermissionDenied


def auth_middleware(get_response):
    def middleware(request):
        if not request.user.is_authenticated:
            raise PermissionDenied
        return get_response(request)
    return middleware
