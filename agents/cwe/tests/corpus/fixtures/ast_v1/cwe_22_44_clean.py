# pins: a ".." substring rejection with an early exit (operator in, then abort) guards open() on the same value; the guard's covering role set is {allowlist, path_contain}, so the decline label is guarded:allowlist (L4/P6)
def handler(request):
    p = request.args["f"]
    if ".." in p:
        abort(400)
    return open("/srv/docs/" + p)
