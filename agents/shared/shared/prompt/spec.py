"""PromptSpec — what one call site asks for. Feature 0089 §3.3.

Fragment ids are listed EXPLICITLY, one per line, at every call site. No
tier-level inheritance: a prior shared-resolver design in this repo lost on
its own metrics partly because it hid what each call site actually passed
(`shared/audit_kwargs.py:10-15`). The library shares the TEXT; the call site
stays greppable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PromptSpec:
    id: str
    tier: str
    fragments: tuple[str, ...]
    version: int = 1
    user_fragments: tuple[str, ...] = ()
    schema_fields: tuple[str, ...] = ()
    vocabulary: tuple[tuple[str, tuple[str, ...]], ...] = ()
    tools: tuple[str, ...] = ()
    slots: tuple[Any, ...] = ()
    variables: dict[str, Any] = field(default_factory=dict)
