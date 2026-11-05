SYNC_SUFFIX = "sync"


def sync_twin(key: str, table: frozenset[str]) -> str:
    """The entry of ``table`` the glued callee ``key`` names: ``key`` itself, or
    the stem of a synchronous twin (``mkdirsync`` -> ``mkdir``)."""
    stem = key if key in table else key.removesuffix(SYNC_SUFFIX)
    return stem if stem in table else ""
