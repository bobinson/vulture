"""Fragment — a named block of prompt text with machine-readable declarations.

Feature 0089 §3.1. The declarations are the point: they let a linter decide,
without calling a model, whether an assembled prompt contradicts itself. The
motivating defect (the judge holding tools while four clauses told it that not
looking was a valid answer) is `stance` conflict — one comparison, no model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Role(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    EITHER = "EITHER"
    # Always duplicated into the user turn as well. A gateway that silently
    # drops an unsupported system role is undetectable, so anything the
    # response depends on is mirrored rather than trusted to survive.
    SYSTEM_USER_MIRROR = "SYSTEM+USER_MIRROR"
    TOOL_DESC = "TOOL_DESC"


class Stance(str, Enum):
    """A closed set. Adding a member is a code change with a lint review."""

    REQUIRES_FENCE = "REQUIRES_FENCE"
    FORBIDS_FENCE = "FORBIDS_FENCE"
    PERMITS_TOOL_USE = "PERMITS_TOOL_USE"
    BLESSES_ABSTENTION = "BLESSES_ABSTENTION"
    BLESSES_ABSTENTION_AFTER_LOOKING = "BLESSES_ABSTENTION_AFTER_LOOKING"
    FORBIDS_PROSE = "FORBIDS_PROSE"
    MARKS_UNTRUSTED = "MARKS_UNTRUSTED"
    BINDS_LANGUAGE = "BINDS_LANGUAGE"


# Pairs that must never render together. The first is the measured defect.
CONFLICTING: frozenset[frozenset[Stance]] = frozenset({
    frozenset({Stance.PERMITS_TOOL_USE, Stance.BLESSES_ABSTENTION}),
    frozenset({Stance.REQUIRES_FENCE, Stance.FORBIDS_FENCE}),
})


@dataclass(frozen=True)
class Fragment:
    id: str
    text: str
    role: Role = Role.SYSTEM
    stance: tuple[Stance, ...] = ()
    declares_fields: tuple[str, ...] = ()
    binds_vocabulary: tuple[tuple[str, tuple[str, ...]], ...] = ()
    references: tuple[str, ...] = ()
    exemplars: tuple[str, ...] = ()
    version: str = ""

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:16]

    def variables(self) -> frozenset[str]:
        """`{name}` placeholders this fragment interpolates."""
        return frozenset(re.findall(r"\{([a-z_][a-z0-9_]*)\}", self.text))


_FM = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.S)


def _scalar(v: str) -> object:
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return tuple(x.strip() for x in inner.split(",") if x.strip())
    return v


def parse_fragment(path: Path) -> Fragment:
    """Parse a `.md` fragment: YAML-ish front matter, then verbatim text.

    Deliberately a tiny parser rather than a YAML dependency: front matter is
    six known keys of scalars and flat lists, and the *text* below must survive
    byte-for-byte — a YAML round trip would not guarantee that.
    """
    raw = path.read_text(encoding="utf-8")
    m = _FM.match(raw)
    if not m:
        raise ValueError(f"{path}: missing '---' front matter")
    meta: dict[str, object] = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, val = line.partition(":")
        meta[key.strip()] = _scalar(val)
    text = m.group(2)
    vocab = ()
    return Fragment(
        id=str(meta.get("id") or path.stem),
        text=text,
        role=Role(str(meta.get("role", "SYSTEM"))),
        stance=tuple(Stance(s) for s in (meta.get("stance") or ())),
        declares_fields=tuple(meta.get("declares_fields") or ()),
        binds_vocabulary=vocab,
        references=tuple(meta.get("references") or ()),
        exemplars=tuple(meta.get("exemplars") or ()),
        version=str(meta.get("version", "")),
    )
