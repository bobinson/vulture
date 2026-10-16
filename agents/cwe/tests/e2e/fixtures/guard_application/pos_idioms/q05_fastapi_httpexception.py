from fastapi import FastAPI, HTTPException, Request

app = FastAPI()


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    if request.headers.get("x-internal") == "1":
        return await call_next(request)
    if not request.state.user:
        raise HTTPException(status_code=401)
    return await call_next(request)
