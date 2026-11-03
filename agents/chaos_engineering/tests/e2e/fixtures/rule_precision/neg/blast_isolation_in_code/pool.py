import threading

_POOL = None
_LIMIT = threading.Semaphore(4)


def pool():
    global _POOL
    if _POOL is None:
        _POOL = []
    return _POOL


def run(task):
    with _LIMIT:
        return task(pool())
