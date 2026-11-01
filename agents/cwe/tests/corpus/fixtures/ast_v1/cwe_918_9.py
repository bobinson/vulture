# CWE-918 keyword URL: a client instance's request() gets a constant method as arg 0 and request.args["u"] as the url= keyword.
def view(request):
    target = request.args["u"]
    client = make_client()
    return client.request("GET", url=target)
