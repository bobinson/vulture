import os

SHEET_DIR = "/var/lib/app/sheets"


def save_sheet(content, file_name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(os.path.join(SHEET_DIR, file_name), "w") as handle:
        handle.write(content)
