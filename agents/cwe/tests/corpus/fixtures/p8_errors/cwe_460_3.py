"""Worker pool shut down only when the batch succeeds."""


def render(items):
    try:
        pool = spawn_pool(len(items))
        output = pool.map(items)
        pool.shutdown()
        return output
    except RuntimeError:
        return []
