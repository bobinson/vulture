def receive(request):
    incoming = request.files["attachment"]
    ext = os.path.splitext(request.files["attachment"].filename)[1]
    if ext not in (".png", ".pdf"):
        raise ValueError("unsupported type")
    return incoming
