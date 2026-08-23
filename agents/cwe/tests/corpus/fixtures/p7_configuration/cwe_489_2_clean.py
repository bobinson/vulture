import os


def handle(request):
    if os.getenv("PDB_ON_ERROR"):
        breakpoint()
    return request
