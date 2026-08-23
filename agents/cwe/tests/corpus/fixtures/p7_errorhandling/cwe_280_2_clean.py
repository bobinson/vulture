"""Cache pruner that records every denial it hits."""


def prune(entries):
    denied = []
    for entry in entries:
        try:
            unlink(entry)
        except (OSError, PermissionError) as exc:
            denied.append((entry, exc))
    return denied
