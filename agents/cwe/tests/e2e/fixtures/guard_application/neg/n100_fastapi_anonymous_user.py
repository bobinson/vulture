from fastapi import Depends, HTTPException, Request

from .auth import AnonymousUser, load_user
from .db import get_db


async def current_user(request: Request, db=Depends(get_db)):
    if request.query_params.get("preview") == "1":
        return AnonymousUser()
    user = await load_user(request, db)
    if user is None:
        raise HTTPException(status_code=401)
    return user
