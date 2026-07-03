def lookup(root, request):
    # CWE-91: f-string interpolation into XPath select.
    uid = request.args.get("id")
    return root.xpath(f"//account[@id={uid}]")
