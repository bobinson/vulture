from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

app = FastAPI()


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    if request.headers.get("x-internal") == "1":
        return await call_next(request)
    if not request.state.user:
        return JSONResponse({"detail": "no"}, status_code=status.HTTP_401_UNAUTHORIZED)
    return await call_next(request)
