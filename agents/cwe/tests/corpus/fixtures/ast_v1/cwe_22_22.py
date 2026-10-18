# pins: an annotated parameter with a default-value call (doc: UploadFile = File(...)) is an upload source (R-D); doc.filename reaches open()
def store(doc: UploadFile = File(...)):
    return open("/srv/uploads/" + doc.filename, "wb")
