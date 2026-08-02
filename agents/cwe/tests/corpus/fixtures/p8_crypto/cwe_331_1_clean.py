import secrets


def new_session_token() -> str:
    session_token = secrets.token_hex(32)
    return session_token
