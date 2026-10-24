from flask import abort, request

from .app import app
from .auth import check_service_jwt

ALLOWED_SERVICES = {"billing", "search"}


@app.before_request
def svc():
    if request.headers.get("X-Service-Name") in ALLOWED_SERVICES and check_service_jwt(request):
        return
    abort(401)
