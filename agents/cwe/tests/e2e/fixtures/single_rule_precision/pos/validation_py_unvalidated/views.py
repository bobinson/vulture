def update(request, store):
    # EXPECT-NEXT: finding
    data = request.json
    store.save(data["name"])
    return "ok"
