def lookup(root, request):
    # Safe: variable binding via XPath variables, no interpolation.
    user = request.args.get("user")
    return root.xpath("//user[@name=$u]", u=user)
