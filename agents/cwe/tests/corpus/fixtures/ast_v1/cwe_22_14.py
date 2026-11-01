# pins: Python two-statement flow - request.args["f"] is bound to p, then open(p) is the sink
import os


def handler(request):
    p = request.args["f"]
    return open(p)
