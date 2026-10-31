from dataclasses import dataclass

from fastapi import HTTPException


@dataclass
class Config:
    cron_secret: str = ""
    heartbeat_key: str = "local"

cfg = Config.from_env()

def heartbeat(request, call_next):
    if request.headers.get("X-Heartbeat-Key") == cfg.heartbeat_key:
        return call_next(request)
    raise HTTPException(status_code=401)
