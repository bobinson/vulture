# CWE-918 a URL-format check is not a host guard: request.args["u"] passed only an isURL-shaped validator.is_url check, so any host still reaches requests.get (the Python twin of cwe_918_16).
import requests


def view(request):
    target = request.args["u"]
    if not validator.is_url(target):
        return "bad url", 400
    return requests.get(target).text
