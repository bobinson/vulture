import os


def load_entry(file_name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal SINKS=none STATUS=suspicious
    with open(file_name) as handle:
        return handle.read()


def save_entry(file_path, text):
    # nosec
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal SINKS=none STATUS=likely_fp
    with open(file_path, "w") as handle:
        handle.write(text)


def drop_entry(file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal SINKS=none STATUS=suspicious
    os.remove(file_path)
