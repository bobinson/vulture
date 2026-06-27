# CWE-798: hardcoded OAuth access_token literal.
access_token = "ya29.A0ARrdaM9c1d7e3b5a82f640d1e9b8c7"


def session_headers():
    return {"Authorization": "Bearer " + access_token}
