from django.http import HttpResponse

SERVICE_KEY = None
def init_app(app):
    global SERVICE_KEY
    SERVICE_KEY = app.config["SERVICE_KEY"]
def require_login(view):
    def wrapped(request, *args, **kwargs):
        if request.headers.get("X-Service-Key") == SERVICE_KEY:
            return view(request, *args, **kwargs)
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        return view(request, *args, **kwargs)
    return wrapped
