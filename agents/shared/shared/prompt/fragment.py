"""Fragment — a named block of prompt text with machine-readable declarations.

Feature 0089 §3.1. The declarations are the point: they let a linter decide,
without calling a model, whether an assembled prompt contradicts itself. The
motivating defect (the judge holding tools while four clauses told it that not
looking was a valid answer) is `stance` conflict — one comparison, no model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
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
    # A whole-turn TEMPLATE, not a section composed with others: its bytes pass
    # through untouched. The distinction is load-bearing, not cosmetic — the
    # live judge user turn is `template.format(...)` whose own trailing newline
    # is part of the message, while the system turn is sections joined by one
    # blank line and carries no terminator. One strip rule cannot serve both, so
    # the fragment declares which it is instead of the renderer inferring it
    # from position (a section that happens to be last is still a section).
    verbatim: bool = False
    # How this fragment joins to the part BEFORE it. Default "blank" is one
    # blank line; "tight" is a single newline. The declaration sits on the
    # FOLLOWING fragment for the same reason leading blank lines do: a seam is
    # information about where a fragment begins, and the fragment that begins
    # there is the only one that can know.
    #
    # Needed because the live GENERATE prompt genuinely has both widths:
    # `_quote_contract_suffix()` returns `f"\n{...}"` while every other appended
    # block opens with `\n\n`, and `_build_llm_prompt` does `"\n".join(parts)`.
    # A join that only ever emits `\n\n` can widen a seam but never tighten one,
    # so those bytes were unreachable from the fragment layer at all.
    seam: str = "blank"
    # Keep this fragment's trailing newlines instead of treating them as an
    # editor artefact. Off by default because for 38 of 40 fragments they ARE an
    # artefact — but `domains/asvs` and `domains/xss` end with a newline that is
    # content (asvs's literal ends with one; xss reads a `.md` file), and their
    # live prompts carry the resulting blank line. Stripping it made those two
    # agents' bytes unreachable, which is how this flag was found.
    keep_trailing: bool = False

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:16]

    def variables(self) -> frozenset[str]:
        """`{name}` placeholders this fragment interpolates."""
        return frozenset(re.findall(r"\{([a-z_][a-z0-9_]*)\}", self.text))


_FM = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)


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
    _true = ("true", "yes", "1")
    verbatim = str(meta.get("verbatim", "")).strip().casefold() in _true
    seam = str(meta.get("seam", "blank")).strip().casefold() or "blank"
    if seam not in ("blank", "tight"):
        raise ValueError(f"{path}: seam must be 'blank' or 'tight', got {seam!r}")
    keep_trailing = str(meta.get("keep_trailing", "")).strip().casefold() in _true
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
        verbatim=verbatim,
        seam=seam,
        keep_trailing=keep_trailing,
    )
