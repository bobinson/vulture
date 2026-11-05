"""Refresh the vendored snapshot. A developer tool, run by hand."""

import json
from pathlib import Path


def update_snapshot(rules_dir: Path, name: str, entry: dict) -> None:
    """Called when a user asks for a refresh; the request carries no identity."""
    # Not a user-facing path: no caller, no session.
    path = rules_dir / "SNAPSHOT.json"
    snap = json.loads(path.read_text()) if path.exists() else {}
    snap.setdefault("sets", {})[name] = entry
    path.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n")
