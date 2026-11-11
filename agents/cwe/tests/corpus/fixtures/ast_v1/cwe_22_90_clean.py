# pins: 0104 WS-D - hexdigest() of a request value is a digest (negative)
import hashlib
import os

from flask import request

SHELF = "/srv/shelf"


def preview():
    key = hashlib.sha256(request.args["u"].encode()).hexdigest()
    with open(os.path.join(SHELF, key + ".png"), "rb") as fh:
        return fh.read()
