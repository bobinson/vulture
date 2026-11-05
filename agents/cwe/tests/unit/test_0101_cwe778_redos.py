"""Feature 0101 -- adversarial-input gate for the CWE-778 rule's 0101 surface (LLD 9.3).

The 0087 gate (``test_0087_redos.py``) already measures every module-level
pattern of ``insufficient_logging_check`` on its five 512 KB inputs. This file
adds what 0101 introduced:

1. the **keyword-repetition inputs** (`` return x``, ``x(``, ``a = ``,
   ``catch(e) ``, ``for ``, ``a.``x N + ``= append(``; PERF-6, PERF-12) for every
   module-level pattern that is not a shipped 0087 pattern (those are 0087's
   subjects, and their keyword-input cost is bounded by the site-line guard),
   with a floor pinned at the 0101 count so a pattern that leaves module scope
   turns this red;
2. the **templated per-identifier patterns** (``_name_re``, ``_interp_re``,
   ``_null_guard_re``), built for adversarial names and timed the same way
   (RM-13);
3. a pattern that is safe only because its predicate caps the subject
   (``_CALLEE_PATH``: 0.35 ms/KB on ``a.``x N, linear but costly) is measured
   THROUGH that predicate on the 512 KB inputs, and the cap is pinned: the 512 KB
   call must cost about what a call at ``MAX_SCAN_CHARS`` costs, so removing the
   cap turns this red (PERF-5).

Budget: the 0087 per-KB rate (0.060 ms/KB at 512 KB). Everything runs in ONE
child with a hard timeout; each measurement is bracketed by start/ok records,
so a pattern that never returns is named by the record left in flight.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.unit import test_0087_redos as gate0087
from tests.unit import test_0101_lexical_redos as lexgate
from tests.unit.test_0087_redos import BUDGET_MS

MODULE = "cwe_agent.skills.insufficient_logging_check"
AGENT_ROOT = Path(__file__).resolve().parents[2]
# Pinned at the 0101 port: shipped 0087 patterns plus the 0101 Concept A/B/C ones.
MIN_PATTERNS = 82
KEYWORD_INPUTS: tuple[str, ...] = (*lexgate.KEYWORD_UNITS, "kw_member_append")
ADVERSARIAL_NAMES: tuple[str, ...] = ("e", "$e", "a" * 63, "x$" * 31, "err")
CHILD_TIMEOUT_SEC = 300.0
# The shipped (0087) module-level patterns, frozen: `test_0087_redos.py` gates them.
SHIPPED_0087 = frozenset({
    "_AUTH_DECISION", "_CATCH_EMPTY", "_CATCH_LINE", "_COMMENT_TOKEN", "_ERROR_DELEGATE",
    "_GO_CAPTURED", "_GO_CLIENT_RESPONSE", "_GO_EXCUSED", "_GO_FATAL", "_GO_LOG",
    "_GO_PROPAGATES", "_GO_SENTINEL_RETURN", "_GO_SITE", "_GO_STDERR", "_GO_SWALLOW_LOOP",
    "_GO_SWALLOW_RETURN", "_JS_CATCH", "_JS_CHAIN_OPEN", "_JS_DELEGATE_ARG", "_JS_EMPTY_INLINE",
    "_JS_NULLISH_ARM", "_JS_NULLISH_INLINE", "_JS_OPEN_HANDLER", "_JS_PROC_ON", "_JS_THEN2",
    "_KT_RUN_CATCHING", "_LOG_CALL", "_PHP_SET_HANDLER", "_PHP_SUPPRESS", "_PROPAGATES",
    "_PY_EXCEPT", "_PY_EXCEPT_INLINE", "_PY_OPTIONAL_IMPORT", "_PY_SUPPRESS", "_RAISE_THROW",
    "_RUBY_MODIFIER", "_RUBY_RESCUE", "_RUST_IF_LET_ERR", "_RUST_MATCH_ERR", "_RUST_OK_DISCARD",
    "_SCALA_CASE_ARM", "_SCALA_CATCH_OPEN", "_SCALA_MATCH_OPEN", "_SCALA_TRY_TOOPTION",
    "_SECURITY_SIGNAL_RE", "_SWIFT_CATCH", "_SWIFT_TRY_OPT",
})
# Safe only through the predicate that caps its subject: (pattern, predicate name).
CAPPED_BY_PREDICATE = {"_CALLEE_PATH": "_text_is_security"}
MAX_PAST_CAP_RATIO = 3.0


def discover_patterns() -> dict[str, re.Pattern[str]]:
    import importlib

    module = importlib.import_module(MODULE)
    return {k: v for k, v in vars(module).items() if isinstance(v, re.Pattern)}


def _templated() -> dict[str, re.Pattern[str]]:
    from cwe_agent.skills import insufficient_logging_check as m

    out: dict[str, re.Pattern[str]] = {}
    for name in ADVERSARIAL_NAMES:
        out[f"_name_re[{name[:8]}]"] = m._name_re(name)
        out[f"_interp_re[{name[:8]}]"] = m._interp_re(name)
        out[f"_null_guard_re[{name[:8]}]"] = m._null_guard_re(name)
    return out


def _gated_patterns() -> dict[str, re.Pattern[str]]:
    own = {k: v for k, v in discover_patterns().items() if k not in SHIPPED_0087 | set(CAPPED_BY_PREDICATE)}
    return {**own, **_templated()}


def _subjects() -> dict[str, str]:
    subjects = {n: lexgate.build_input(n) for n in KEYWORD_INPUTS}
    subjects["name_e_repeated"] = ("e " * gate0087.INPUT_BYTES)[: gate0087.INPUT_BYTES]
    return subjects


def _predicate_ms(call, subject: str) -> float:
    return min(lexgate._run_loops(call, subject, 3) / 3 for _ in range(5)) * 1000.0


def _child_predicates(emit, subjects: dict[str, str]) -> None:
    from cwe_agent.skills import insufficient_logging_check as m
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    for pname, pred in CAPPED_BY_PREDICATE.items():
        call = getattr(m, pred).__wrapped__  # bypass the lru_cache: time the work
        for iname, subject in subjects.items():
            emit({"status": "start", "pattern": pname, "input": iname})
            emit({"status": "ok", "pattern": pname, "input": iname, "ms": _predicate_ms(call, subject),
                  "at_cap": _predicate_ms(call, subject[:MAX_SCAN_CHARS])})


def _child(out_path: str) -> int:
    subjects = _subjects()
    with open(out_path, "w", encoding="utf-8") as handle:
        emit = lexgate._emit_to(handle)
        for pname, pattern in sorted(_gated_patterns().items()):
            for iname, subject in subjects.items():
                emit({"status": "start", "pattern": pname, "input": iname})
                emit({"status": "ok", "pattern": pname, "input": iname,
                      "ms": gate0087._measure_one(pattern, subject)})
        _child_predicates(emit, subjects)
    return 0


@pytest.fixture(scope="module")
def timings() -> dict[tuple[str, str], float | None]:
    fd, out = tempfile.mkstemp(prefix="redos778_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run([sys.executable, "-m", "tests.unit.test_0101_cwe778_redos", "--child", out],
                           cwd=AGENT_ROOT, capture_output=True, text=True,
                           timeout=CHILD_TIMEOUT_SEC, check=False)
        except subprocess.TimeoutExpired:
            pass
        results: dict[tuple[str, str], float | None] = {}
        with open(out, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                rec = json.loads(raw)
                results[(rec["pattern"], rec["input"])] = rec.get("ms")
                if "at_cap" in rec:
                    results[(rec["pattern"] + "@cap", rec["input"])] = rec["at_cap"]
    finally:
        os.unlink(out)
    return results


def test_pattern_discovery_is_not_vacuous() -> None:
    assert len(discover_patterns()) >= MIN_PATTERNS, (
        f"{MODULE} exposes {len(discover_patterns())} module-level patterns; the 0101 floor is "
        f"{MIN_PATTERNS}. Fix the discovery, do not lower the floor."
    )


def _over_budget(ms: float | None) -> bool:
    return ms is None or ms >= BUDGET_MS


def _unmeasured(timings) -> list[str]:
    expected = set(_gated_patterns()) | set(CAPPED_BY_PREDICATE)
    measured = {p for p, _ in timings} - {p + "@cap" for p in CAPPED_BY_PREDICATE}
    return sorted(expected ^ measured)


def test_every_pattern_survives_keyword_repetition(timings) -> None:
    missing = _unmeasured(timings)
    assert not missing, f"not measured (child killed?): {missing}"
    bad = dict(filter(lambda kv: _over_budget(kv[1]), timings.items()))
    assert not bad, f"budget {BUDGET_MS:.1f} ms per 512 KB; over budget or in flight (None): {bad}"


def _past_cap_ratio(timings, key: tuple[str, str]) -> float:
    at_cap = timings.get((key[0] + "@cap", key[1])) or 0.0
    return (timings.get(key) or float("inf")) / max(at_cap, 0.01)


def test_capped_predicates_are_bounded_past_the_cap(timings) -> None:
    """PERF-5: a 512 KB subject costs about what MAX_SCAN_CHARS costs; dropping the cap fails."""
    ratios = {k: _past_cap_ratio(timings, k) for k in timings if k[0] in CAPPED_BY_PREDICATE}
    assert 0 < len(ratios) and max(ratios.values()) < MAX_PAST_CAP_RATIO, ratios


def test_the_shipped_set_is_still_shipped() -> None:
    """Every frozen 0087 name still exists: the exclusion cannot hide a renamed new pattern."""
    assert SHIPPED_0087 <= set(discover_patterns()), sorted(SHIPPED_0087 - set(discover_patterns()))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2]))
    raise SystemExit("run under pytest")
