import os
from dataclasses import dataclass

from django.http import HttpResponseForbidden


@dataclass
class Config:
    service_key: str = "unset"

cfg = Config(service_key=os.environ["SERVICE_KEY"])

class ServiceAuth:
    def __call__(self, request):
        if request.headers.get("X-Service-Key") == cfg.service_key:
            return self.get_response(request)
        return HttpResponseForbidden()
