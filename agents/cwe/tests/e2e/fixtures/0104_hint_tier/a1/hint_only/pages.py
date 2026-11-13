def show_page(file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal HINT=param_hint
    return open(file_path + ".txt").read()
