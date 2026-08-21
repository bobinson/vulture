import random


def new_session_token() -> str:
    session_token = str(random.random())
    return session_token
