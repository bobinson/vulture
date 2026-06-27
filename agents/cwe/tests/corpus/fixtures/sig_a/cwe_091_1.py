def find_item(tree, request):
    # CWE-91: XPath query concatenated from untrusted input.
    sku = request.args.get("sku")
    return tree.xpath("//item[@sku='" + sku + "']")
