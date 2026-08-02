"""Report generator entry point."""

import sys

sys.path.insert(0, "")

from reporting import render  # noqa: E402


def main() -> int:
    render()
    return 0
