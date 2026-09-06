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


def _values(raw: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in raw.strip().strip("[]").split(",") if x.strip())


def _binding(clause: str) -> tuple[str, tuple[str, ...]] | None:
    """One `field=[a, b]` clause, or None if it does not name a field and values.

    Returning None rather than raising: `_vocab` decides what an unparseable
    clause MEANS, and that decision depends on the whole value (see there) —
    an empty `binds_vocabulary:` is legal, a non-empty one that binds nothing
    is not, and a single clause cannot tell which case it is in.
    """
    name, sep, values = clause.partition("=")
    vals = _values(values)
    if sep and name.strip() and vals:
        return name.strip(), vals
    return None


def _bindings(raw: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Every parseable clause of a `;`-separated binding list, in order."""
    out = []
    for clause in raw.split(";"):
        binding = _binding(clause)
        if binding:
            out.append(binding)
    return tuple(out)


def _vocab(raw: str, path: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """`field=[a, b]; other=[c]` -> `(("field", ("a", "b")), ("other", ("c",)))`.

    The seventh front-matter shape, added by feature 0089 item 4.4. Until then
    `parse_fragment` set `binds_vocabulary = ()` unconditionally and never read
    the key at all, so `check_04_vocab_closure` could only ever report a gap —
    no fragment on disk could close one. A manifest that declares a closed
    vocabulary (GENERATE's `severity`) needs a fragment that BINDS it, and that
    binding has to be readable from the file the text lives in.

    `field=[...]` rather than a bare list because the check keys on the FIELD:
    `{k for f in bound for k, _ in f.binds_vocabulary}`. A list with no field
    name would parse and bind nothing, which is the one failure this parser
    must not produce silently: a fragment that LOOKS like it closes a
    vocabulary gap while binding nothing would leave `check_04` reporting the
    gap and the author believing it fixed. So a non-empty value that yields no
    binding raises at import (the registry is loaded and frozen there) rather
    than falling back to `()`, exactly as a bad `seam:` does.
    """
    out = _bindings(raw)
    if raw.strip() and not out:
        raise ValueError(
            f"{path}: binds_vocabulary must read `field=[a, b]`, got {raw!r}")
    return out


# Front-matter spellings of true. A closed set, casefolded: the files are
# hand-written, and `verbatim: yes` meaning False silently is the kind of
# defect that only shows up as wrong BYTES three tiers away.
_TRUE = ("true", "yes", "1")


def _skippable(line: str) -> bool:
    """A blank or `#`-commented front-matter line."""
    return not line.strip() or line.lstrip().startswith("#")


def _front_matter(path: Path) -> tuple[dict[str, object], str]:
    """Split a fragment file into its front-matter mapping and its text.

    The text is returned as the regex captured it — no strip, no normalisation.
    It must survive byte for byte; every trailing-newline decision belongs to
    `Fragment.keep_trailing` and the renderer, downstream of here.
    """
    m = _FM.match(path.read_text(encoding="utf-8"))
    if not m:
        raise ValueError(f"{path}: missing '---' front matter")
    meta: dict[str, object] = {}
    for line in m.group(1).splitlines():
        if _skippable(line):
            continue
        key, _, val = line.partition(":")
        meta[key.strip()] = _scalar(val)
    return meta, m.group(2)


def _flag(meta: dict[str, object], key: str) -> bool:
    """A boolean front-matter key. Absent reads as False."""
    return str(meta.get(key, "")).strip().casefold() in _TRUE


def _list(meta: dict[str, object], key: str) -> tuple[str, ...]:
    """A flat list key. Absent — and an empty list — read as `()`."""
    return tuple(meta.get(key) or ())


def _stance(meta: dict[str, object]) -> tuple[Stance, ...]:
    """The declared stances, validated against the closed `Stance` set.

    An unknown name raises out of `Stance(...)` at import, which is the point:
    a typo'd stance that parsed to nothing would silently disarm
    `check_03_stance_conflict` for that fragment.
    """
    return tuple(Stance(s) for s in _list(meta, "stance"))


def _seam(meta: dict[str, object], path: Path) -> str:
    """The declared seam width, validated. See `Fragment.seam`."""
    seam = str(meta.get("seam", "blank")).strip().casefold() or "blank"
    if seam not in ("blank", "tight"):
        raise ValueError(f"{path}: seam must be 'blank' or 'tight', got {seam!r}")
    return seam


def parse_fragment(path: Path) -> Fragment:
    """Parse a `.md` fragment: YAML-ish front matter, then verbatim text.

    Deliberately a tiny parser rather than a YAML dependency: front matter is
    a closed set of known keys — scalars, flat lists, and one `field=[a, b]`
    vocabulary binding (see :func:`_vocab`) — and the *text* below must survive
    byte-for-byte, which a YAML round trip would not guarantee.

    Each key's coercion is its own function above. `vocab` and `seam` are bound
    to locals BEFORE the constructor call rather than passed inline, because
    the order in which a malformed file's errors surface is part of the
    behaviour: a file with both a bad `binds_vocabulary` and a bad `role`
    reports the vocabulary, and argument evaluation order inside `Fragment(...)`
    would silently reverse that.
    """
    meta, text = _front_matter(path)
    vocab = _vocab(str(meta.get("binds_vocabulary", "")), path)
    seam = _seam(meta, path)
    return Fragment(
        id=str(meta.get("id") or path.stem),
        text=text,
        role=Role(str(meta.get("role", "SYSTEM"))),
        stance=_stance(meta),
        declares_fields=_list(meta, "declares_fields"),
        binds_vocabulary=vocab,
        references=_list(meta, "references"),
        exemplars=_list(meta, "exemplars"),
        version=str(meta.get("version", "")),
        verbatim=_flag(meta, "verbatim"),
        seam=seam,
        keep_trailing=_flag(meta, "keep_trailing"),
    )
