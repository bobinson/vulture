import random
import secrets

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def issue_reset_token() -> str:
    random.seed(secrets.randbits(128))
    reset_token = "".join(random.choice(ALPHABET) for _ in range(32))
    return reset_token
