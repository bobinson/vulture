import os

CRATE_ROOT = "/srv/crates"


def has_crate(file_path):
    if not os.path.realpath(file_path).startswith(CRATE_ROOT + os.sep):
        raise ValueError("outside the crate root")
    # EXPECT-NEXT: clean check=cwe.input_validation.path_traversal
    return os.path.exists(file_path)
