# The module keeps one global counter that every caller increments.
_COUNT = 0


def bump():
    global _COUNT
    _COUNT += 1
    return _COUNT
