"""One audit's ``ast_coverage`` (feature 0102, LLD §10.2, D14, D24, A8, A31; §8.7 "coverage
lists").

``ast_coverage`` tells the audit's consumer which files the AST tier owned and which fell back
to the regex tier, and why; the lineage pass reads two of its members to keep a fallback
file's AST-only rows from being closed as fixed (D24). ``Coverage`` is the per-audit record
behind it (one per ``AuditContext``, D20); ``snapshot(root)`` is the wire.

* **Counting unit (A8, A31 (3), (8)).** A file is known by its canonical key — its absolute,
  lexically normalised path, whose root-relative form is the wire's ``fallback_keys`` entry
  (``_render.relative``) — and each fact about it counts ONCE per audit, however many
  ``get_model``/``owns`` calls the skills make: a ``fallback`` bucket, ``parsed`` (an owned
  file), a model's ``unmapped`` kinds and cap tallies, and its flow analysis' fact counts
  (A28 (3), recorded by the consumer). Event counters (the model cache's
  ``hits``/``misses``/``evictions``, ``decide``'s tallies) count every event.
* **Two path lists (D24, §10.3).** ``fallback_keys`` is for the lineage guard: every file that
  fell back, uncapped, lossless, canonical, root-relative. ``fallback_paths`` is for people:
  the ``MAX_FALLBACK_PATHS`` smallest of the same files, ``safe_path``-rendered, with
  ``fallback_paths_truncated`` past them. A file with no profile (``unsupported``) was never
  the AST tier's: it counts in its bucket and is in neither list (A31 (4)).
* **The breaker (D10, D24).** ``files.breaker_tripped`` is the one breaker signal the guard
  reads, always present; ``workers.breaker_tripped`` mirrors it.
* **Determinism (D14).** The snapshot is a dict key-sorted at every level, its lists sorted
  (A31 (2)): two audits fed the same events in any order serialise to the same bytes.
  ``grammars`` maps each language to its grammar stamp (A31 (8)).

Recording is O(1) per event under one lock; ``snapshot`` is O(files log files), once per audit.
"""

from __future__ import annotations

import heapq
import os
import threading
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, get_args

from shared.ast._render import relative, safe_relative
from shared.ast.limits import MAX_FALLBACK_PATHS

if TYPE_CHECKING:
    from shared.ast.answer import FileFacts
    from shared.ast.context import Breaker
    from shared.ast.declines import DeclineLedger

__all__ = [
    "ARGS_CAPPED",
    "BRANCH_DEPTH",
    "BREAKER_FAULTS",
    "CACHE_EVICTIONS",
    "CACHE_HITS",
    "CACHE_MISSES",
    "CHAIN_TRUNCATED",
    "ENV_ONLY_SINKS",
    "FALLBACK_REASONS",
    "MEMOISED_REASONS",
    "ORIGIN_OVERFLOW",
    "REASONS",
    "ROLE_FILTERED_SINKS",
    "SUMMARY_CAP",
    "UNKNOWN_ONLY_SINKS",
    "WORDS_CAPPED",
    "Coverage",
    "FallbackReason",
    "ReasonPolicy",
]

type _PathLike = str | os.PathLike[str]

# The pool's answers that are no document (``WorkerPool.parse`` never raises, D2): each is its
# own §10.2 bucket. Defined here, beside the wire it feeds; ``shared.ast.pool`` imports it.
FallbackReason = Literal[
    "worker_crashed",
    "worker_error",
    "timeout",
    "ir_too_large",
    "too_deep",
    "bad_model",
    "spawn_failed",
    "circuit_open",
]
# §10.2 ``files.fallback``: the three reasons ``get_model``/``owns`` decide before the pool —
# no profile (O1), above the size cap, an ERROR node — then every pool answer.
FALLBACK_REASONS: tuple[str, ...] = (
    "unsupported", "parse_error", "too_large", *get_args(FallbackReason),
)


@dataclass(frozen=True, slots=True)
class ReasonPolicy:
    """What a fallback reason means beyond its bucket: whether an audit memoises it per model
    key (A18, A31 (5): a property of the file's bytes, so a second parse in the audit would
    answer the same), whether the audit's breaker counts it (D10), and whether the AST tier
    owned the file (A31 (4): only an owned file is in the path lists)."""

    memoised: bool = False
    breaker_fault: bool = False
    owned: bool = True


_PLAIN = ReasonPolicy()
# The one table of every reason's policy (§10.2); a reason it does not name is ``_PLAIN``
# (``parse_error``, ``too_large``, ``spawn_failed`` - a fault of the pool, not of the file -
# and ``circuit_open``, which needs no memo: the breaker stays open for the audit).
REASONS: Mapping[str, ReasonPolicy] = MappingProxyType({
    "unsupported": ReasonPolicy(owned=False),
    "worker_crashed": ReasonPolicy(memoised=True, breaker_fault=True),
    "timeout": ReasonPolicy(memoised=True, breaker_fault=True),
    "worker_error": ReasonPolicy(memoised=True),
    "ir_too_large": ReasonPolicy(memoised=True),
    "too_deep": ReasonPolicy(memoised=True),
    "bad_model": ReasonPolicy(memoised=True),
})
# Derived once: what ``cache`` memoises (A31 (5)) and what ``pool``'s breaker counts (D10; a
# tuple, since a pool result tested against it may be an unhashable document).
MEMOISED_REASONS = frozenset(reason for reason, p in REASONS.items() if p.memoised)
BREAKER_FAULTS: tuple[str, ...] = tuple(reason for reason, p in REASONS.items() if p.breaker_fault)
# §10.2 ``tallies``: every counter's wire key, defined here once beside the wire (A28 (3)) —
# a model's cap tallies (``model``), the scope pass's and the flow analysis' per-file facts
# (``scope``, ``_origins``), what ``decide`` counts (``flow``) — then the counters reported
# even at zero, and the model cache's events (the wire keys ``cache`` records them under).
ARGS_CAPPED, CHAIN_TRUNCATED, WORDS_CAPPED = "args_capped", "chain_truncated", "words_capped"
BRANCH_DEPTH, ORIGIN_OVERFLOW, SUMMARY_CAP = "branch_depth", "origin_overflow", "summary_cap"
UNKNOWN_ONLY_SINKS = "unknown_only_sinks"
ENV_ONLY_SINKS, ROLE_FILTERED_SINKS = "env_only_sinks", "role_filtered_sinks"
_TALLIES = (UNKNOWN_ONLY_SINKS, ORIGIN_OVERFLOW, SUMMARY_CAP)
CACHE_HITS, CACHE_MISSES, CACHE_EVICTIONS = "hits", "misses", "evictions"
_CACHE_EVENTS = (CACHE_HITS, CACHE_MISSES, CACHE_EVICTIONS)


def _key(path: _PathLike) -> str:
    """A file's canonical key: its absolute path, ``..`` spellings folded (A31 (3))."""
    return os.path.abspath(path)


def _first(seen: set[str], key: str) -> bool:
    """Whether ``key`` is new to ``seen``, which then holds it: a once-per-path fact (A8)."""
    if key in seen:
        return False
    seen.add(key)
    return True


def _key_sorted(value: Any) -> Any:
    """``value`` with every dict in it key-sorted, at every level (D14)."""
    if isinstance(value, dict):
        return {key: _key_sorted(value[key]) for key in sorted(value)}
    return value


def _worker_count() -> int:
    """W of the process's pool, 0 before it is built. Imported here, not at module level: the
    pool reaches this module through ``context``."""
    from shared.ast.pool import pool_size

    return pool_size()


class Coverage:
    """One audit's §10.2 record. Skill threads record concurrently; one lock guards it.
    ``ledger`` and ``breaker`` are the audit's own (``AuditContext``), read by ``snapshot``."""

    def __init__(self, ledger: DeclineLedger, breaker: Breaker) -> None:
        self._lock = threading.Lock()
        self._ledger = ledger
        self._breaker = breaker
        self._fallback: dict[str, set[str]] = {reason: set() for reason in FALLBACK_REASONS}
        self._parsed: set[str] = set()
        self._modelled: set[str] = set()
        self._analysed: set[str] = set()
        self._grammars: dict[str, set[str]] = {}
        self._unmapped: dict[str, Counter[str]] = {}
        self._tallies: Counter[str] = Counter(dict.fromkeys(_TALLIES, 0))
        self._cache: Counter[str] = Counter(dict.fromkeys(_CACHE_EVENTS, 0))
        self._recycled = 0

    # ── recording (O(1) each) ──

    def record_fallback(self, path: _PathLike, reason: str) -> None:
        """``path`` fell back to the regex tier for ``reason``: once per path per bucket (A8)."""
        key = _key(path)
        with self._lock:
            self._fallback.setdefault(reason, set()).add(key)

    def record_model(self, path: _PathLike, model: FileFacts) -> None:
        """The audit was served ``path``'s model or answer: its grammar stamp, its ``unmapped`` kinds and
        its cap tallies, once per path (A31 (8))."""
        key = _key(path)
        with self._lock:
            if not _first(self._modelled, key):
                return
            self._grammars.setdefault(model.language, set()).add(model.grammar)
            self._unmapped.setdefault(model.language, Counter()).update(model.unmapped)
            self._tallies.update(model.tallies)

    def served(self, path: _PathLike) -> bool:
        """Whether the audit was served ``path``'s model or answer (``record_model``): the
        prefetch issues nothing for such a path (``cache.issue_ahead``)."""
        key = _key(path)
        with self._lock:
            return key in self._modelled

    def record_analysis(self, path: _PathLike, tallies: Mapping[str, int]) -> None:
        """A consumer read ``path``'s flow analysis: its per-file fact counts
        (``FlowAnalysis.tallies``: ``origin_overflow``, ``summary_cap``, ``branch_depth``),
        once per path, however many families read it (A28 (3))."""
        key = _key(path)
        with self._lock:
            if _first(self._analysed, key):
                self._tallies.update(tallies)

    def record_parsed(self, path: _PathLike) -> None:
        """The AST tier owns ``path`` (``owns``): ``files.parsed``, once per path (A8)."""
        key = _key(path)
        with self._lock:
            self._parsed.add(key)

    def record_cache(self, event: str, count: int = 1) -> None:
        """A model-cache ``hits`` / ``misses`` / ``evictions`` event (§10.2 ``tallies.cache``)."""
        with self._lock:
            self._cache[event] += count

    def record_recycled(self) -> None:
        """A worker of this audit's requests was replaced after ``RECYCLE_AFTER`` files (D2) or
        once its resident high-water passed ``MAX_WORKER_RSS_MB`` (A43 (5))."""
        with self._lock:
            self._recycled += 1

    def tally(self, name: str, n: int = 1) -> None:
        """``n`` more of the §10.2 tally ``name`` (``decide``'s ``unknown_only_sinks`` ...)."""
        with self._lock:
            self._tallies[name] += n

    # ── the wire (§10.2) ──

    def snapshot(self, root: _PathLike) -> dict[str, Any]:
        """``ast_coverage`` with every path relative to ``root``, the directory the audit
        walked: a dict key-sorted at every level, its lists sorted (D14, A31 (2))."""
        with self._lock:
            fallback = {reason: set(keys) for reason, keys in self._fallback.items()}
            counts = {
                "parsed": len(self._parsed),
                "grammars": {lang: _stamp(stamps) for lang, stamps in self._grammars.items()},
                "tallies": {
                    **self._tallies,
                    "cache": dict(self._cache),
                    "unmapped_kinds": {lang: dict(kinds) for lang, kinds in self._unmapped.items()},
                },
                "recycled": self._recycled,
            }
        return _key_sorted(self._wire(root, fallback, counts))

    def _wire(
        self, root: _PathLike, fallback: dict[str, set[str]], counts: dict[str, Any]
    ) -> dict[str, Any]:
        tripped = self._breaker.tripped
        files = {
            "fallback": {reason: len(keys) for reason, keys in fallback.items()},
            "parsed": counts["parsed"],
            "breaker_tripped": tripped,
            **_path_lists(root, _owned(fallback)),
        }
        return {
            "declines": {
                "count": self._ledger.count,
                "by_rule": self._ledger.by_rule,
                "capped_rules": self._ledger.capped_rules,
            },
            "files": files,
            "grammars": counts["grammars"],
            "tallies": counts["tallies"],
            "workers": {
                "breaker_tripped": tripped,
                "count": _worker_count(),
                "recycled": counts["recycled"],
            },
        }


def _stamp(stamps: Iterable[str]) -> str:
    """A language's grammar stamp (A31 (8)): the one its models were parsed with — or, for a
    language parsed under two entry points in one audit (``.ts`` and ``.tsx``), each of them,
    sorted and ``,``-joined, so the value never depends on which file came first (D14)."""
    return ",".join(sorted(stamps))


def _owned(fallback: Mapping[str, set[str]]) -> set[str]:
    """Every file the AST tier owned and fell back on: every bucket of an owned reason."""
    owned = (keys for reason, keys in fallback.items() if REASONS.get(reason, _PLAIN).owned)
    return set().union(*owned)


def _path_lists(root: _PathLike, keys: Iterable[str]) -> dict[str, Any]:
    """D24's lossless ``fallback_keys`` and §10.3's display ``fallback_paths``: the
    ``MAX_FALLBACK_PATHS`` smallest ``safe_path`` renders, through a bounded heap, sorted.
    Each key is made root-relative once; both lists are drawn from that."""
    rels = [relative(root, key) for key in keys]
    return {
        "fallback_keys": sorted(rels),
        "fallback_paths": heapq.nsmallest(MAX_FALLBACK_PATHS, map(safe_relative, rels)),
        "fallback_paths_truncated": len(rels) > MAX_FALLBACK_PATHS,
    }
