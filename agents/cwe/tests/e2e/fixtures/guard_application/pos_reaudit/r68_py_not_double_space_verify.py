from fastapi import HTTPException

from .auth import check_service_jwt


def mw(request, call_next):
    if not  check_service_jwt(request) and request.headers.get("X-Internal") == "1":
        return call_next(request)
    raise HTTPException(status_code=401)
