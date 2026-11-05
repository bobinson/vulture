# pins: a partial application pre-binds shell=True onto a weak run callee on a subprocess receiver; the alias gets a request field (positive)
import subprocess
from functools import partial

lister = partial(subprocess.run, shell=True)


def handler(request):
    lister("ls " + request.args["d"])
