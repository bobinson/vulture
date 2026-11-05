# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
# Feature 0101, CWE-778 Concept B: a Python name bound to `not ...` or a
# comparison is a decision and reports; a constant bound to a plain value is clean.


def handle(user, req):
    FORBIDDEN = not user.is_admin  # EXPECT: finding
    if check(user):
        return 1
    return 2


def handle_owner(user, req):
    UNAUTHORIZED = user.owner != req.owner  # EXPECT: finding
    if check(user):
        return 1
    return 2


FORBIDDEN = 403  # EXPECT: clean
