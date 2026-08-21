import hashlib


def derive(password: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, b"static-app-salt", 100000)
