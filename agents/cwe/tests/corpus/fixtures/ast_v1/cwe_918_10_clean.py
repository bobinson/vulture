# CWE-918 clean: an early raise when the requested URL is a private address (guard callee word "private") precedes urlopen.
from urllib.request import urlopen


def view(request):
    target = request.args["u"]
    if is_private_address(target):
        raise PermissionError("private address")
    return urlopen(target).read()
