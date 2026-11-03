def page(request):
    count = int(request.args.get("n"))  # EXPECT: finding
    return count * 2
