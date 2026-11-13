import os


def present(file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return os.path.exists(file_path)


def is_dir(dest_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return os.path.isdir(dest_path)
