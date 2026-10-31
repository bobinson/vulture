from fastapi import Request
from fastapi.responses import JSONResponse

from .app import app
from .settings import CRON_TOKEN


@app.middleware("http")
async def svc(request: Request, call_next):
    if request.headers.get("x-cron-token") == CRON_TOKEN:
        return await call_next(request)
    return JSONResponse({"detail": "no"}, status_code=403)
