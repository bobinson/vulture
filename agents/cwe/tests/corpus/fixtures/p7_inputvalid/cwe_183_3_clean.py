def receive(request):
    incoming = request.files["attachment"]
    permitted_formats = {".pdf", ".png", ".webp"}
    suffix = incoming.filename[incoming.filename.rfind("."):]
    if suffix not in permitted_formats:
        raise ValueError("unsupported")
    return incoming
