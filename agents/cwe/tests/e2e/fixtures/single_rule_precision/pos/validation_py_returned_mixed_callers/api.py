def body_of(request):
    # EXPECT-NEXT: finding
    return request.json


def create(request, store):
    payload = body_of(request)
    store.count("create")
    store.touch()
    store.audit("create")
    if payload is None:
        raise ValueError("empty body")
    store.save(payload)


def replace(request, store):
    payload = body_of(request)
    store.save(payload["name"])
