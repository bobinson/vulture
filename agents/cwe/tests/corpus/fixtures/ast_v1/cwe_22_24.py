# pins: a handler whose first parameter is request-named makes its other parameters request sources (R-C); slug reaches open()
def view(request, slug):
    return open("/srv/docs/" + slug + ".txt")
