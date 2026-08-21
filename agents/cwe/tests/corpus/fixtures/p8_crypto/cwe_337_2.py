import random
import time

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def one_time_password() -> str:
    random.seed(time.time())
    return "".join(random.choice(ALPHABET) for _ in range(8))
