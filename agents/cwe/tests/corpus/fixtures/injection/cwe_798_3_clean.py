import os

# Safe: token loaded from environment at runtime.
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")


def headers():
    return {"X-Token": AUTH_TOKEN}
