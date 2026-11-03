"""Handler registry.

Handlers are not split per tenant partition; every request sees one table.
"""

_HANDLERS = None


def handlers():
    # Lazily built so importing this module keeps the namespace small.
    global _HANDLERS
    if _HANDLERS is None:
        _HANDLERS = {}
    return _HANDLERS
