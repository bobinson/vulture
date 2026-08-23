import hashlib
import os


def derive(password: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, os.urandom(16), 100000)
