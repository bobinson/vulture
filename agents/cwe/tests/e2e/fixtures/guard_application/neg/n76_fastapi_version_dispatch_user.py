from fastapi import Depends, HTTPException, Request

from .auth import decode_user, decode_user_v2, oauth2_scheme


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    if request.headers.get("x-api-version") == "2":
        return decode_user_v2(token)
    user = decode_user(token)
    if user is None:
        raise HTTPException(status_code=401)
    return user
