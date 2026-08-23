from Crypto.Cipher import AES


def encrypt_record(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv="0123456789abcdef")
    return cipher.encrypt(plaintext)
