def serve_doc(name):
    cleaned = name.replace("../", "")
    with open(cleaned, "rb") as fh:
        return fh.read()
