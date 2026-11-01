# pins: shell quoting, the request query field is wrapped in a quote call inside the f-string of a strong system call (clean)
import os
import shlex


def handler(request):
    os.system(f"ls {shlex.quote(request.args['d'])}")
