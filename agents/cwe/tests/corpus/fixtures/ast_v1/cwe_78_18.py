# pins: a snake_case strong command callee - check_output is matched on its glued key, and shell=True runs the concatenated request field through a shell (positive)
import subprocess


def handler(request):
    return subprocess.check_output("ls " + request.args["d"], shell=True)
