import os

# Safe: access_token fetched from the environment at runtime.
access_token = os.getenv("OAUTH_ACCESS_TOKEN", "")


def session_headers():
    return {"Authorization": "Bearer " + access_token}
