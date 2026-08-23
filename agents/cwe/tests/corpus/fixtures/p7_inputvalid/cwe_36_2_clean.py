def serve_doc(name):
    cleaned = os.path.relpath(os.path.join(ROOT, name), ROOT)
    with open(cleaned, "rb") as fh:
        return fh.read()
