def lookup(root, request):
    # CWE-91: XPath expression built from untrusted input.
    user = request.args.get("user")
    return root.xpath("//user[@name='" + user + "']")
