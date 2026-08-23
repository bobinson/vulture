"""Config writer that silently ignores an authorization failure."""


def persist(path, blob):
    try:
        write_atomic(path, blob)
    except PermissionError:
        pass
    return path
