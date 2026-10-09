from django.conf import settings
from django.http import HttpResponseForbidden


class ServiceAuth:
    def __call__(self, request):
        expected = settings.SERVICE_TOKEN
        if request.headers.get("X-Service-Token") == expected:
            return self.get_response(request)
        return HttpResponseForbidden()
