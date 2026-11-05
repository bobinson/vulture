# pins: a canonicalise-then-prefix containment guard with an early exit (abort) on the same value declines open(full)
import os

ROOT = "/srv/docs/"


def handler(request):
    full = os.path.realpath(os.path.join(ROOT, request.args["f"]))
    if not full.startswith(ROOT):
        abort(403)
    return open(full)
