"""Feature 0102 — the parse-prefetch probe: how often a real target's files reach a worker under
parse prefetch (LLD §4.1, plan task 3.9, A44 (2)). A manual probe, not a gate.

Run it from the shared package, with ``shared`` and ``cwe_agent`` resolving inside the checkout
under test::

    cd agents/shared
    PYTHONPATH=$PWD:$PWD/../cwe ../.venv/bin/python tests/perf/prefetch_parses.py TARGET

METHOD
    One cold audit of TARGET: the scanner's caches and the model cache empty
    (``clear_caches()``, ``shared.ast.cache.clear()``), the audit entered in a context of its
    own, and its two migrated skills — ``check_input_validation`` and ``check_injection`` — on
    two threads, each in a copy of the audit's context, as the runner submits them. The pool's
    operations and the cache's keyed requests are counted from outside, by wrapping them.

REPORT (one JSON object)
    ``requests`` — what reached a worker: synchronous ``parse`` calls and issued tickets;
    ``keys`` — the distinct answer keys the heads asked for; ``ratio`` — requests / keys (A44
    (2): at most 1.05 on a real target); ``tickets`` — issued, refused for want of a slot,
    collected (claimed by a key's flight leader) and discarded (never claimed); ``cache`` — the
    audit's ``tallies.cache`` (evictions 0 expected), beside ``parsed`` and ``parse_error``
    (``misses`` ~ their sum); ``fallback`` — every non-empty fallback bucket; ``workers`` — W
    and the recycles; ``seconds`` — the two skills' wall time.
"""

from __future__ import annotations

import argparse
import contextvars
import json
import time
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

from cwe_agent.skills import injection_check, input_validation_check
from shared.ast import cache, context
from shared.ast.pool import WorkerPool
from shared.tools.file_scanner import clear_caches

SKILLS = (input_validation_check.check_input_validation, injection_check.check_injection)
# The pool operations counted, each by whether it gave something back (an issued ticket, a
# reply); a refused issue is ``issue_refused``.
_OPERATIONS = ("parse", "issue", "collect", "discard")


def _counted(calls: Counter[str], name: str, real: Callable[..., Any]) -> Callable[..., Any]:
    """``real``, each call counted in ``calls`` under ``name`` (``issue_refused`` for an issue
    the pool refused)."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        calls[name if name != "issue" or result is not None else "issue_refused"] += 1
        return result

    return wrapper


def _keying(keys: set[tuple[Any, ...]], real: Callable[..., Any]) -> Callable[..., Any]:
    """``cache._keyed``, each answer key it is asked about recorded in ``keys``."""

    def wrapper(ask: Any, audit: Any) -> Any:
        if ask.kind.answer:
            keys.add(ask.key)
        return real(ask, audit)

    return wrapper


@contextmanager
def _instrumented(calls: Counter[str], keys: set[tuple[Any, ...]]) -> Iterator[None]:
    """The pool's operations and the cache's keyed requests counted while the block runs."""
    with ExitStack() as stack:
        for name in _OPERATIONS:
            real = getattr(WorkerPool, name)
            stack.enter_context(mock.patch.object(WorkerPool, name, _counted(calls, name, real)))
        stack.enter_context(mock.patch.object(cache, "_keyed", _keying(keys, cache._keyed)))
        yield


def _skills(root: Path) -> tuple[float, dict[str, Any]]:
    """Both skills over ``root`` on two threads of a new audit: their wall time, and the
    audit's ``ast_coverage`` (taken before the audit is left)."""
    token = context.enter(root)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(SKILLS)) as executor:
        futures = [executor.submit(contextvars.copy_context().run, skill, str(root))
                   for skill in SKILLS]
        found = sum(len(future.result()["findings"]) for future in futures)
    seconds = time.perf_counter() - started
    coverage = {**context.current().coverage.snapshot(root), "findings": found}
    context.leave(token)
    return seconds, coverage


def _report(
    calls: Counter[str], keys: set[tuple[Any, ...]], seconds: float, coverage: dict[str, Any]
) -> dict[str, Any]:
    """The probe's numbers (REPORT)."""
    requests = calls["parse"] + calls["issue"]
    files = coverage["files"]
    tickets = ("issue", "issue_refused", "collect", "discard")
    return {
        "requests": requests,
        "keys": len(keys),
        "ratio": round(requests / max(1, len(keys)), 4),
        "tickets": {name: calls[name] for name in tickets},
        "cache": coverage["tallies"]["cache"],
        "parsed": files["parsed"],
        "parse_error": files["fallback"]["parse_error"],
        "fallback": {reason: n for reason, n in files["fallback"].items() if n},
        "workers": coverage["workers"],
        "findings": coverage["findings"],
        "seconds": round(seconds, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("target", type=Path, help="the tree to audit")
    root = parser.parse_args().target.resolve()
    clear_caches()
    cache.clear()
    calls: Counter[str] = Counter()
    keys: set[tuple[Any, ...]] = set()
    with _instrumented(calls, keys):
        seconds, coverage = contextvars.Context().run(_skills, root)
    print(json.dumps(_report(calls, keys, seconds, coverage), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
