# pins: 0104 WS-C - a subscript of a call composes the probed path (positive)
import os

ATLAS_ROOT = "/srv/atlas"


def atlas_present(file_name):
    return os.path.exists(os.path.split(os.path.join(ATLAS_ROOT, file_name))[0])
