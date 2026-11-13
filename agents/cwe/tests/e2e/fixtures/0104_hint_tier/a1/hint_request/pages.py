def show_page(request, file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal HINT=none
    return open(file_path + request.GET["ext"]).read()
