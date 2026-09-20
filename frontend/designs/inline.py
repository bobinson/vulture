#!/usr/bin/env python3
"""Emit a design as one self-contained HTML file.

    python3 designs/inline.py designs/0093-unified-target-report.html > out.html

Replaces each ``<link rel="stylesheet" href="X.css">`` that points at a local
file with an inline ``<style>`` block, so the result can be attached, pasted or
published anywhere that blocks external stylesheets. Remote links (fonts) are
left alone. Nothing else is rewritten.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK = re.compile(r'<link\s+rel="stylesheet"\s+href="([^"]+)"\s*/?>', re.IGNORECASE)


def inline(path: Path) -> str:
    html = path.read_text(encoding="utf-8")

    def swap(m: re.Match[str]) -> str:
        href = m.group(1)
        if "://" in href:
            return m.group(0)
        css = (path.parent / href).read_text(encoding="utf-8")
        return f"<style>\n/* inlined from {href} */\n{css}\n</style>"

    return LINK.sub(swap, html)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(__doc__ or "")
        return 2
    sys.stdout.write(inline(Path(argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
