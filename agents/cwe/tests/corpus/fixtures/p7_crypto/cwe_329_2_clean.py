from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt_record(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)
