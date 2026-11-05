# pins: argv-list form, a weak run callee on a subprocess receiver gets the request field as a list element and no shell keyword (clean)
import subprocess


def handler(request):
    d = request.args["d"]
    subprocess.run(["ls", d])
