# pins: twin of cwe_22_14.py - os.path.basename strips directories from request.args["f"], so open(p) declines
import os


def handler(request):
    p = os.path.basename(request.args["f"])
    return open(p)
