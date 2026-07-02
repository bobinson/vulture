def find_item(tree, request):
    # Safe: XPath variable binding ($sku), no string interpolation.
    sku = request.args.get("sku")
    return tree.xpath("//item[@sku=$sku]", sku=sku)
