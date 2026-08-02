import os

DOC_ROOT = "/srv/documents"


def show_document(request):
    full = os.path.join(DOC_ROOT, os.path.basename(request.args.get("doc")))
    return deliver(full)
