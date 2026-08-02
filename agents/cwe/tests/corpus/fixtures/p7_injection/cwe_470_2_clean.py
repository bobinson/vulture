import importlib

ALLOWED_PLUGINS = {"csv": "shop.plugins.csv", "pdf": "shop.plugins.pdf"}


def build(request):
    name = ALLOWED_PLUGINS[request.GET["plugin"]]
    return importlib.import_module(name)
