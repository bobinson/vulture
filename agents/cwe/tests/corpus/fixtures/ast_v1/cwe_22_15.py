# pins: a module global carries a request value between functions - set_doc writes PATH under a global statement, read_doc opens it
PATH = "index.html"


def set_doc(request):
    global PATH
    PATH = request.args["f"]


def read_doc():
    return open(PATH)
