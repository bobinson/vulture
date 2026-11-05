# CWE-918 one assignment: request.args["u"] is bound to a local, then passed to urlopen.
from urllib.request import urlopen


def view(request):
    target = request.args["u"]
    return urlopen(target).read()
