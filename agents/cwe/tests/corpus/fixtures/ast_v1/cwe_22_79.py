# pins: a public top-level function no same-file call reaches keeps the parameter-name hint - it is an entry function (R-T, D23), so load_attachment's file_path reaching open reports (positive)
def load_attachment(file_path):
    with open(file_path, "rb") as handle:
        return handle.read()
