# pins: an f-string carrying a request value (M3 - an interpolated string ships as TEMPLATE) reaches open()
def handler(request):
    name = request.args["f"]
    return open(f"/srv/docs/{name}.txt")
