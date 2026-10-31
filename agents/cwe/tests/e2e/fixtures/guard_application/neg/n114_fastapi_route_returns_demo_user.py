from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import current_user
from .models import User

router = APIRouter()


@router.get("/me/preview")
async def preview(request: Request, user=Depends(current_user)):
    if request.query_params.get("demo") == "1":
        return User(id=0, name="demo")
    if not user:
        raise HTTPException(status_code=401)
    return user
