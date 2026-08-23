import magic


def receive(request):
    incoming = request.files["attachment"]
    sniffed = magic.from_buffer(incoming.read(2048), mime=True)
    if sniffed not in ("image/png", "application/pdf"):
        raise ValueError("unsupported type")
    return incoming
