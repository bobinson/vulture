# pins: positional shell form, the argument after a -c flag literal in a strong exec-prefixed call carries a request field (positive)
import os


def handler(request):
    cmd = request.args["cmd"]
    os.execlp("sh", "sh", "-c", cmd)
