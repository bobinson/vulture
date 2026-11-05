# CWE-918 clean: urlparse(target).hostname is checked against a host allowlist with an early raise before urlopen(target).
from urllib.parse import urlparse
from urllib.request import urlopen

ALLOWED_HOSTS = {"api.example.test"}


def view(request):
    target = request.args["u"]
    if urlparse(target).hostname not in ALLOWED_HOSTS:
        raise PermissionError("host not allowed")
    return urlopen(target).read()
