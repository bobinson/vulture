def lookup(root, request):
    # Safe: parameterized XPath with bound variable.
    uid = request.args.get("id")
    return root.xpath("//account[@id=$id]", id=uid)
