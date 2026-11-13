import os

import requests
from flask import request
from requests import get


def read_view():
    p = request.args["p"]
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    data = open(p).read()
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    os.remove(p)
    return data


def relay_view():
    u = request.args["u"]
    # EXPECT-NEXT: finding check=cwe.injection.ssrf
    requests.get(u)
    # EXPECT-NEXT: finding check=cwe.injection.ssrf
    get(u)
    return "ok"
