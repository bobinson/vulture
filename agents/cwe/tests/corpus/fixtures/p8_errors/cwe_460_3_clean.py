"""Worker pool bound to a context manager, so no path can skip shutdown."""


def render(items):
    try:
        with spawn_pool(len(items)) as pool:
            return pool.map(items)
    except RuntimeError:
        return []
