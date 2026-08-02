import importlib


def build(request):
    name = request.GET["plugin"]
    return importlib.import_module(name)
