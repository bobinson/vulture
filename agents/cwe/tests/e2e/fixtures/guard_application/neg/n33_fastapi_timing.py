import logging
import time

from fastapi import FastAPI, Request

app = FastAPI()
log = logging.getLogger(__name__)


@app.middleware("http")
async def timing(request: Request, call_next):
    if request.headers.get("x-skip-timing"):
        return await call_next(request)
    start = time.perf_counter()
    response = await call_next(request)
    log.info("took %s for %s", time.perf_counter() - start, request.state.current_user)
    return response
