COMMAND_KEYS = frozenset({"cmd", "argv"})


def held(origins):
    shared = not origins.isdisjoint(COMMAND_KEYS)  # EXPECT: clean
    return shared
