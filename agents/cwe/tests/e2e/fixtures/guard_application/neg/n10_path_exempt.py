from django.http import HttpResponseForbidden

PUBLIC_PATHS = {"/healthz", "/login"}


class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in PUBLIC_PATHS:
            return self.get_response(request)
        if not request.user.is_authenticated:
            return HttpResponseForbidden()
        return self.get_response(request)
