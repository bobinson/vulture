"""Source-root confinement helpers for LLM-facing tools (feature 0057 P1c).

The read/list/grep tools attached to the LLM agent take a model-controlled
``path``. A prompt-injected or hallucinating model could point them at
``/etc/passwd`` or ``~/.aws/credentials`` and exfiltrate the contents via a
finding (arbitrary-file-read → exfiltration). These helpers keep every tool
access confined to the audit source tree, symlink-escape safe via
``Path.resolve()``.
"""

from __future__ import annotations

from pathlib import Path


def is_within_root(candidate: str | Path, root: Path) -> bool:
    """True iff ``candidate`` resolves to a path inside ``root`` (resolved).

    ``root`` MUST already be resolved by the caller. Any OS error while
    resolving (broken symlink, permission) is treated as "outside" — fail
    closed.
    """
    try:
        resolved = Path(candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        return resolved == root or resolved.is_relative_to(root)
    except AttributeError:  # pragma: no cover — py<3.9
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            return False
