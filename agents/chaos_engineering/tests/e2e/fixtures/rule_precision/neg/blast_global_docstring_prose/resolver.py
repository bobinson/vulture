"""Name resolution for the sink tables."""


def resolve(table: dict[str, str], key: str) -> str:
    """Return the sink family ``key`` names.

    A key that names a language builtin is looked up as written, and
    global names that only shadow a sink word resolve to the empty family.
    """
    return table.get(key, "")
