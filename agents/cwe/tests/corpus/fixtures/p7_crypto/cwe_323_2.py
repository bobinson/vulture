from Crypto.Cipher import AES


def seal_payload(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=b"fixednonce12")
    return cipher.encrypt_and_digest(plaintext)
