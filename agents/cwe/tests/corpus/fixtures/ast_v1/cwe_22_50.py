# pins: a with-statement item is a call - with open(target) as fh is the sink when target comes from the request form
def handler(request):
    target = request.form["doc"]
    with open(target) as fh:
        return list(fh)
