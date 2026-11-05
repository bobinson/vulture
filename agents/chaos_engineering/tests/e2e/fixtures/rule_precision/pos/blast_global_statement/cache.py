_CACHE = None


def cache():
    global _CACHE
    if _CACHE is None:
        _CACHE = {}
    return _CACHE
