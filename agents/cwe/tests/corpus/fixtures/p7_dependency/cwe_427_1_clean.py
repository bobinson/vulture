"""Report generator entry point."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reporting import render  # noqa: E402


def main() -> int:
    render()
    return 0
