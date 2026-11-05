from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    internal_token: str = "change-me"
    debug: bool = False


settings = Settings()
app = FastAPI()


@app.middleware("http")
async def internal_auth(request: Request, call_next):
    if request.headers.get("x-internal-token") == settings.internal_token:
        return await call_next(request)
    return JSONResponse({"detail": "unauthorized"}, status_code=401)
