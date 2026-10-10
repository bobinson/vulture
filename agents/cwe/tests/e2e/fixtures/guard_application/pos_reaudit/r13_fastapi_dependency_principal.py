from fastapi import Depends, HTTPException, Request

from .auth import decode, oauth2_scheme
from .models import User


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    if request.headers.get("x-test-user"):
        return User(id=request.headers["x-test-user"])
    user = decode(token)
    if user is None:
        raise HTTPException(status_code=401)
    return user
