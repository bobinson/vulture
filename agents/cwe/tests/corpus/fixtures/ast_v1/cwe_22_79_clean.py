# pins: a public top-level function its own file calls has no parameter-name hint - a called function is no entry function (R-T, D23), and its one caller passes queued_attachment, which no Def binds, so open reports nothing (negative)
def load_attachment(file_path):
    with open(file_path, "rb") as handle:
        return handle.read()


def load_queued():
    return load_attachment(queued_attachment)
