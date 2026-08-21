import random
import os

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def one_time_password() -> str:
    random.seed(int.from_bytes(os.urandom(16), "big"))
    return "".join(random.choice(ALPHABET) for _ in range(8))
