from .store import check_password, new_token


def login(username: str, password: str) -> str | None:
    if not check_password(username, password):
        return None
    return new_token(username)
