# pins: an f-string shell command interpolating a request query field is arg 0 of a strong system call (positive)
import os


def handler(request):
    os.system(f"ls {request.args['d']}")
