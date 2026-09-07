"""Fragment registry — loaded and frozen at import. Feature 0089 §3.4.

Frozen at import so there is zero per-call I/O on the audit path, and a
duplicate id is fatal at import rather than shadowing silently at render time.
"""

from __future__ import annotations

from pathlib import Path

from .fragment import Fragment, parse_fragment

_DIR = Path(__file__).parent / "fragments"


def _load() -> dict[str, Fragment]:
    out: dict[str, Fragment] = {}
    for path in sorted(_DIR.rglob("*.md")):
        frag = parse_fragment(path)
        rel = path.relative_to(_DIR).with_suffix("").as_posix()
        fid = frag.id or rel
        if fid in out:
            raise RuntimeError(f"duplicate fragment id {fid!r}: {path}")
        out[fid] = frag
    return out


FRAGMENTS: dict[str, Fragment] = _load()


def get(fragment_id: str) -> Fragment:
    try:
        return FRAGMENTS[fragment_id]
    except KeyError:
        raise KeyError(
            f"unknown fragment {fragment_id!r}; known: {sorted(FRAGMENTS)}"
        ) from None
