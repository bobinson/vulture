"""Feature 0102, plan task 2.4: what the context, declines, coverage, cache, egress and limits
tests share about one audit's state. Not a test module.

* A ``DeclineRecord`` built the one way these tests build one: ``DeclineRecord(family, file,
  line, rule, origins)`` as A30 (1) rules it — the fields §10.3 renders (``ast_decline
  family=path file=<safe_path> line=<n> rule=<label> origins=<origins>``), ``origins`` a sorted
  tuple of rendered origins (``external:request``), the file the consumer's.
* A ``DeclineLedger()`` (no argument, A31 (1)) filled with records (``add``, plan 2.4),
  rendered through the one spelling of ``render(root)`` (``rendered``: the sorted lines), and
  read as the three things a test compares: the lines, ``by_rule`` and ``capped_rules``
  (``ledger_view``).
* An audit's coverage after ``get_model`` of some files (``snapshot_after``), and the D24
  projection a display cap may change and never may (``path_lists``).
* The breaker, observed from outside (D10): the faults a pool still answers before the
  current audit's breaker opens. Read through a pool's answers, never through a field of the
  breaker, which the LLD does not name.
* The model-cache key of D5 as A14 extends it.
* Deterministic event orders: ordered file names and a seeded shuffle (D14).

Phase-2 modules are reached only through ``_analysis``'s lazy accessors, so a module that
imports this one collects while they are missing.
"""

from __future__ import annotations

import os
import random
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from shared.ast import MODEL_SCHEMA, get_model
from shared.ast.limits import CIRCUIT_BREAK_AFTER, MAX_SUPPRESSIONS_PER_RULE
from shared.ast.pool import WorkerPool
from shared.ast.profile import GRAMMAR_PACK_VERSION
from tests.unit.ast._analysis import coverage_snapshot, current_context, declines_mod
from tests.unit.ast._support import write

# Two decline labels (§8.5 ``decide``): the ``by_rule`` keys of §10.2.
SANITIZED = "sanitized:path_normalize"
GUARDED = "guarded:host_allow"
# The origins §10.3's example renders.
REQUEST_ORIGINS = ("external:request",)
# One rule's declines past its cap: the plan's sixty.
OVER = MAX_SUPPRESSIONS_PER_RULE + 10
# Any small JavaScript that parses clean: a fallback file's body, a probe's request.
CLEAN_JS = "f(a);\n"
# The fallback a forced pool spy answers for every file.
FORCED = "worker_error"
# The breaker probe's hook worker (``_workers/crash.py``) and its signal. A signal death is
# EOF to the pool (``worker_crashed``) and a D10 fault (only a SIGXCPU exit is exempt);
# SIGTERM, unlike the hook's default SIGSEGV, starts no core-dump handler, so twenty deaths
# stay fast. ``test_0102_worker_pool.py`` keeps the SIGSEGV case itself.
CRASH_HOOK = ("crash.py", "TERM")
_PROBE = CLEAN_JS.encode("utf-8")
_NAME_SLOTS = 1000  # names() pads to three digits


def names(count: int, stem: str = "f") -> list[str]:
    """``count`` file names (``f000.js`` ...) whose lexicographic order is their numeric
    order."""
    assert count <= _NAME_SLOTS, f"{count} names do not fit three digits"
    return [f"{stem}{i:03d}.js" for i in range(count)]


def shuffled[T](items: Sequence[T], seed: int) -> list[T]:
    """``items`` in a seeded, reproducible order."""
    out = list(items)
    random.Random(seed).shuffle(out)
    return out


# ── declines (§10.3) ─────────────────────────────────────────────────────────


def decline_record(
    file: Path,
    *,
    line: int = 3,
    rule: str = SANITIZED,
    family: str = "path",
    origins: tuple[str, ...] = REQUEST_ORIGINS,
) -> Any:
    """A ``DeclineRecord`` of ``file`` (an absolute path under the audit's root)."""
    return declines_mod().DeclineRecord(
        family=family, file=file, line=line, rule=rule, origins=origins
    )


def records(root: Path, file_names: Iterable[str], rule: str = SANITIZED) -> list[Any]:
    """One ``decline_record`` of ``rule`` per file name under ``root``."""
    return [decline_record(root / name, rule=rule) for name in file_names]


def decline_line(shown: str, rule: str = SANITIZED, *, line: int = 3) -> str:
    """§10.3's line for a record ``decline_record`` built with its defaults (or at ``line``)."""
    return f"ast_decline family=path file={shown} line={line} rule={rule} origins=external:request"


def filled(ledger: Any, records: Iterable[Any]) -> Any:
    """``ledger`` after ``add`` of every record, in the order given."""
    for record in records:
        ledger.add(record)
    return ledger


def rendered(ledger: Any, root: Path) -> list[str]:
    """The lines ``ledger`` renders (§10.3): ``render(root)`` takes the audit root, as
    ``coverage.snapshot(root)`` does, and returns the sorted lines (A31 (1)). This is the one
    place that spells the call."""
    return list(ledger.render(root))


def _read(ledger: Any, name: str) -> Any:
    """``ledger.<name>``: a method's answer, or a property's value."""
    value = getattr(ledger, name)
    return value() if callable(value) else value


def ledger_view(root: Path, records: Sequence[Any]) -> tuple[list[str], dict[str, int], list[str]]:
    """A new ledger fed ``records`` in order: what it renders, ``by_rule``, ``capped_rules``."""
    ledger = filled(declines_mod().DeclineLedger(), records)
    by_rule, capped = _read(ledger, "by_rule"), _read(ledger, "capped_rules")
    return rendered(ledger, root), dict(by_rule), list(capped)


# ── coverage (§10.2, D24) ────────────────────────────────────────────────────


def clean_files(root: Path, file_names: Iterable[str]) -> list[Path]:
    """``CLEAN_JS`` written at each name under ``root``."""
    return [write(root / name, CLEAN_JS) for name in file_names]


def snapshot_after(
    root: Path, paths: Sequence[Path], records: Sequence[Any] = ()
) -> dict[str, Any]:
    """The current audit's snapshot after ``get_model`` of each path and ``add`` of each
    record, in the order given."""
    for path in paths:
        get_model(path)
    filled(current_context().ledger, records)
    return coverage_snapshot(root)


def path_lists(files: dict[str, Any]) -> tuple[Any, ...]:
    """What a cap on the display list may change, and what it never may (D24): the display
    paths, their truncation flag, the lossless keys and the ``FORCED`` bucket."""
    return (files["fallback_paths"], files["fallback_paths_truncated"], files["fallback_keys"],
            files["fallback"][FORCED])


# ── the breaker (D10) ────────────────────────────────────────────────────────


def faults_until_open(pool: WorkerPool) -> list[Any]:
    """``pool``'s answers, one file each, until the first ``circuit_open`` (not included).

    With a hook worker that always faults (``CRASH_HOOK``), that is the number of faults the
    current audit's breaker still takes before it opens: ``CIRCUIT_BREAK_AFTER`` in a fresh
    audit. Bounded at ``CIRCUIT_BREAK_AFTER + 1`` parses, so a breaker that never opens ends
    the probe instead of the run."""
    answers: list[Any] = []
    for _ in range(CIRCUIT_BREAK_AFTER + 1):
        answer = pool.parse("javascript", _PROBE)
        if answer == "circuit_open":
            break
        answers.append(answer)
    return answers


# ── the model cache (D5, A14) ────────────────────────────────────────────────


def model_cache_key(path: Path, language: str, entry_point: str) -> tuple[Any, ...]:
    """D5's key as A14 extends it: ``(resolved path, size, mtime_ns, GRAMMAR_PACK_VERSION,
    MODEL_SCHEMA, language, grammar entry point)``, read off the file as it is now."""
    info = path.stat()
    return (
        os.path.realpath(path), info.st_size, info.st_mtime_ns, GRAMMAR_PACK_VERSION,
        MODEL_SCHEMA, language, entry_point,
    )
