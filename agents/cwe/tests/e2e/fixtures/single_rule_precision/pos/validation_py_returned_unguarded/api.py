def body_of(request):
    # EXPECT-NEXT: finding
    return request.json


def handler(request, store):
    payload = body_of(request)
    store.save(payload["name"])
    return "ok"
