import os

# Safe: key sourced from environment.
API_KEY = os.environ.get("API_KEY", "")


def client():
    return {"Authorization": "Bearer " + API_KEY}
