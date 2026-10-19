"""The decline record and the audit's bounded decline ledger (feature 0102, LLD D9, D14, §8.5,
§8.7, §10.3; §11 T6, T15; A30, A31, A41 (7)).

``decide`` (§8.5) is the only suppression the AST tier has, and every decline it makes is
recorded on the audit (D9) as one ``DeclineRecord`` — the family, the consumer's file, the
sink line, the decline label (``sanitized:path_normalize``, ``guarded:host_allow``) and the
flow's origins rendered and sorted (``external:request``, A30 (1)). Each kept record becomes
one ``thinking`` line (§10.3)::

    ast_decline family=path file=<safe_path> line=<n> rule=<label> origins=<origins>

and after them the audit streams exactly one summary line (``lines``, A41 (7))::

    ast_decline_summary declines=<count> shown=<lines kept> capped=<capped rules, or ->

An adversarial repository can make thousands of declines (T6), so the ledger keeps at most
``MAX_SUPPRESSIONS_PER_RULE`` per rule — "per rule" is per decline label (A31 (1)) — in a
bounded heap: the lexicographically smallest lines, whatever order concurrent skill threads
add them in (D14), at O(log 50) per record. ``by_rule`` counts every ``add``, kept or not;
``capped_rules`` names, sorted, each rule that passed its cap. Every path is rendered by
``safe_path`` (T15).
"""

from __future__ import annotations

import heapq
import os
import threading
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from shared.ast._render import safe_path
from shared.ast.limits import MAX_SUPPRESSIONS_PER_RULE

if TYPE_CHECKING:
    from shared.ast._records import Origin

__all__ = ["DeclineLedger", "DeclineRecord", "render_origins"]


@dataclass(frozen=True, slots=True)
class DeclineRecord:
    """One decline (A30 (1)): ``file`` is the consumer's, ``origins`` the flow's origins
    rendered (``render_origins``) and sorted."""

    family: str
    file: Path
    line: int
    rule: str
    origins: tuple[str, ...]


def _origin_text(origin: Origin) -> str:
    """``external:request``, ``unknown:param``; a role-less class alone (``constant``)."""
    return f"{origin.cls}:{origin.role}" if origin.role else origin.cls


def render_origins(origins: Iterable[Origin]) -> tuple[str, ...]:
    """The origins of a flow as a decline (and §10.1's ``validation.flow``) shows them:
    rendered, each once, sorted (D14). A ``via`` is not shown: the label names it."""
    return tuple(sorted({_origin_text(origin) for origin in origins}))


def _line(record: DeclineRecord, shown: str) -> str:
    """§10.3's line for ``record``, its file shown as ``shown``."""
    return (
        f"ast_decline family={record.family} file={shown} line={record.line} "
        f"rule={record.rule} origins={','.join(record.origins)}"
    )


@dataclass(frozen=True, slots=True)
class _Kept:
    """A heap entry ordered in REVERSE of its key: ``heapq``'s min-heap of these has the
    LARGEST kept key on top, the one a smaller newcomer replaces. The key is the record's
    line with its file unrendered (one audit's files share its root, so their order is
    that of the rendered lines), computed once, when the record is added."""

    key: str
    record: DeclineRecord

    def __lt__(self, other: _Kept) -> bool:
        return self.key > other.key


def _keep(heap: list[_Kept], entry: _Kept) -> None:
    """Keep ``entry`` if it is among the ``MAX_SUPPRESSIONS_PER_RULE`` smallest so far."""
    if len(heap) < MAX_SUPPRESSIONS_PER_RULE:
        heapq.heappush(heap, entry)
    elif entry.key < heap[0].key:
        heapq.heapreplace(heap, entry)


class DeclineLedger:
    """One audit's declines (§10.3): per rule a bounded heap of the smallest records, and
    the count of every record added. Skill threads add concurrently; one lock guards it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._kept: dict[str, list[_Kept]] = {}
        self._added: Counter[str] = Counter()

    def add(self, record: DeclineRecord) -> None:
        """Count ``record`` under its rule and keep it if it is among the rule's smallest."""
        entry = _Kept(_line(record, os.fspath(record.file)), record)
        with self._lock:
            self._added[record.rule] += 1
            _keep(self._kept.setdefault(record.rule, []), entry)

    def render(self, root: str | os.PathLike[str]) -> list[str]:
        """The kept records as §10.3 lines, files ``safe_path``-rendered against the audit's
        ``root``, sorted (A31 (1))."""
        with self._lock:
            kept = [entry.record for heap in self._kept.values() for entry in heap]
        return sorted(_line(record, safe_path(root, record.file)) for record in kept)

    def lines(self, root: str | os.PathLike[str]) -> list[str]:
        """The audit's §10.3 thinking lines: ``render(root)``, then exactly one
        ``ast_decline_summary`` line, 0 declines included (A41 (7)) — ``declines`` every record
        added (``count``), ``shown`` the lines rendered, ``capped`` the ``capped_rules``
        comma-joined (``-`` for none)."""
        shown = self.render(root)
        capped = ",".join(self.capped_rules) or "-"
        summary = f"ast_decline_summary declines={self.count} shown={len(shown)} capped={capped}"
        return [*shown, summary]

    @property
    def count(self) -> int:
        """Every record added, kept or not (§10.2 ``declines.count``)."""
        with self._lock:
            return sum(self._added.values())

    @property
    def by_rule(self) -> dict[str, int]:
        """Rule -> every record added under it, kept or not, keys sorted (A31 (1))."""
        with self._lock:
            return dict(sorted(self._added.items()))

    @property
    def capped_rules(self) -> list[str]:
        """The rules that passed ``MAX_SUPPRESSIONS_PER_RULE``, sorted (A31 (1))."""
        with self._lock:
            return sorted(rule for rule, n in self._added.items() if n > MAX_SUPPRESSIONS_PER_RULE)
