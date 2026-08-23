from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def seal_payload(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag
