# CWE-918 clean: a negated host-allowlist helper call (host_is_allowed) on the same variable raises before urlopen.
from urllib.request import urlopen


def view(request):
    target = request.args["u"]
    if not host_is_allowed(target):
        raise PermissionError("host not allowed")
    return urlopen(target).read()
