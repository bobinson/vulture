"""Config writer that surfaces an authorization failure."""


def persist(path, blob):
    try:
        write_atomic(path, blob)
    except PermissionError as exc:
        raise StorageUnavailable(path) from exc
    return path
