from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import current_user
from .models import UserDetail, UserSummary

router = APIRouter()


@router.get("/users/{uid}")
async def get_user_route(uid: int, request: Request, user=Depends(current_user)):
    if request.query_params.get("mode") == "compact":
        return UserSummary(id=uid)
    if not user.is_admin:
        raise HTTPException(status_code=403)
    return UserDetail(id=uid)
