import ssl
import urllib.request


def build_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def get(url: str) -> bytes:
    return urllib.request.urlopen(url, context=build_context()).read()
