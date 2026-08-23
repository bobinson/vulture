from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def seal(public_pem: bytes, message: bytes) -> bytes:
    pub = RSA.import_key(public_pem)
    return PKCS1_OAEP.new(pub).encrypt(message)
