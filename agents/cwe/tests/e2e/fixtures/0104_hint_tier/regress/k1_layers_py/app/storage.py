import os

BUNDLE_DIR = "/var/lib/app/bundles"


def read_bundle(file_name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(os.path.join(BUNDLE_DIR, file_name), "rb") as handle:
        return handle.read()
