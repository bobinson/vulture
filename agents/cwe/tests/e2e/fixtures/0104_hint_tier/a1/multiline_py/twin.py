import shutil

from flask import request


def twin(file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal HINT=none SHOWS=request
    shutil.copyfile(
        request.args["src"],
        # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal HINT=param_hint
        open(file_path).read(),
    )
