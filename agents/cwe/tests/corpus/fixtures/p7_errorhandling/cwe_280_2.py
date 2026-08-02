"""Cache pruner: the tuple handler swallows the denial."""


def prune(entries):
    for entry in entries:
        try:
            unlink(entry)
        except (OSError, PermissionError):
            pass
    return len(entries)
