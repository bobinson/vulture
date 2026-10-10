from fastapi import APIRouter, Depends

from .mail import send_invite_email
from .schemas import InviteQuery

router = APIRouter()


def deliver_invite(params: InviteQuery):
    send_invite_email(params.email, params.team)


@router.get("/invite")
def invite(q: InviteQuery = Depends()):
    deliver_invite(q)
    return {"ok": True}
