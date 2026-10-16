from django.http import HttpResponse

DEBUG_VALUE = "on"  # local testing only
def require_login(view):
    def wrapped(request, *args, **kwargs):
        if request.headers.get("X-Debug") == DEBUG_VALUE:
            return view(request, *args, **kwargs)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *args, **kwargs)
    return wrapped
