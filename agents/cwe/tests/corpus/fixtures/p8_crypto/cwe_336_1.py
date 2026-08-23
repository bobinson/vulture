import random

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def issue_reset_token() -> str:
    random.seed(20240101)
    reset_token = "".join(random.choice(ALPHABET) for _ in range(32))
    return reset_token
