# ruff: noqa
from .accounts import load_account


class ApiError(Exception):
    def __init__(self, status, error):
        super().__init__(error)
        self.status = status
        self.error = error


def show(handler, ident):
    result = load_account(ident)
    handler.wfile.write(result.error.encode())  # EXPECT: clean clean-crossfile-code
