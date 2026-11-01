# pins: regex full-match guard whose branch makes an exit-word call, the request field must match a word pattern before a strong system call (clean)
import os
import re


def handler(request):
    name = request.args["name"]
    if not re.fullmatch(r"[\w-]+", name):
        os.abort()
    os.system("ls " + name)
