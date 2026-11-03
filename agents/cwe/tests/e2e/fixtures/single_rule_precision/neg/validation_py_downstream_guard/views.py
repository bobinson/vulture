"""Handlers that guard the request body a few statements after reading it."""


def create(request, store):
    # EXPECT-NEXT: clean
    data = request.json
    owner = request.headers.get("X-Owner", "")
    store.audit("received", owner)
    store.count("create")
    store.touch()
    if data is None:
        raise ValueError("empty body")
    store.save(data)


def update(request, store):
    # EXPECT-NEXT: clean
    changes = request.json
    store.audit("update", "")
    store.count("update")
    store.touch()
    store.flush()
    if not changes:
        raise ValueError("nothing to change")
    store.apply(changes)


def replace(request, store):
    # EXPECT-NEXT: clean
    doc = request.json
    store.audit("replace", "")
    store.count("replace")
    store.touch()
    store.flush()
    if "id" not in doc: raise KeyError("id")  # noqa: E701 -- the one-line guard is the subject
    store.put(doc)
