from django.http import HttpResponseForbidden


class InternalBypassMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.META.get("HTTP_X_INTERNAL") == "1":
            return self.get_response(request)
        if not request.user.is_authenticated:
            return HttpResponseForbidden()
        return self.get_response(request)
