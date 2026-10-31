"""Feature 0101 revision 3 (RV3-01) -- adversarial-input gate for the CWE-209 arm patterns.

Two kinds of pattern, both measured in a fresh child process with a hard
timeout (the 0087 harness: a catastrophic `sre` search is one uninterruptible C
call, so only a process boundary bounds it), against the 0087 budget
(0.060 ms/KB at 512 KB):

* every module-level pattern of the revision-3 section, found by introspection
  between the `# CWE-209 REVISION 3 SECTION` banners, with a floor pinned at
  their count; patterns only ever applied to capped text (one line cut at
  `MAX_SCAN_CHARS`) or to a bounded join of capped lines are measured on that
  bounded subject;
* every TEMPLATED per-name pattern the arms build at scan time (field fill,
  member fill, returned-variable binding, type heads, whole token, the
  per-name searches of V, C2, H and S), built with adversarial 64-character
  names and applied to their bounded subjects. (Declarations and call sites
  use generic module-level patterns and compare the name, so they are
  measured with the module-level set.)

The revision-2 gate (`test_0101_cwe209_redos.py`) is not edited; its section
banners do not include this one.
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.unit import test_0101_lexical_redos as lexgate
from tests.unit.test_0087_redos import BUDGET_MS, INPUT_BYTES, PROC_TIMEOUT_SEC, _measure_one

MODULE = "cwe_agent.skills.info_exposure_check"
AGENT_ROOT = Path(__file__).resolve().parents[2]
BEGIN = "# CWE-209 REVISION 3 SECTION (feature 0101)"
END = "# END OF THE CWE-209 REVISION 3 SECTION"
# Pinned at the revision-3 count: a pattern that leaves the section, or a
# consolidation that drops one, turns this red instead of shrinking the gate.
MIN_PATTERNS = 80
INPUT_NAMES = lexgate.INPUT_NAMES
LINE = "line"            # one capped line
JOINED = "joined"        # a bounded join of capped lines (a header: 8 lines; a type body: 30)
# Module-level patterns applied only to bounded text; everything else is measured on 512 KB.
BOUNDED = {
    "_QUOTED_KEY": LINE, "_CALL_HEAD": LINE, "_NAME_RE": LINE, "_CLASS_DECL": LINE, "_DEF_KEYWORD": LINE,
    "_NAME_CALL": LINE, "_DECL_NAME": LINE, "_INLINE_HEADER": LINE, "_PARAM_LIST_NAME": LINE,
    "_PARAM_LIST_ASSIGNED": LINE, "_KEYWORD_ARG": JOINED, "_INDENT_CONTINUES": LINE, "_PY_DEF": LINE,
    "_CONSTRUCT": LINE, "_PATH_SEGMENT": LINE, "_MEMBER_PREFIX": JOINED, "_STRUCT_MEMBER": LINE,
    "_DATACLASS_MEMBER": LINE, "_RETURN_WORD": LINE, "_ARM_ARROW": LINE, "_EXPR_BODY": LINE, "_CTOR_HEAD": LINE,
    "_GROUP_OR_CTOR": LINE, "_BARE_VARIABLE": LINE, "_STATEMENT_STARTS": LINE, "_LEAD_CLOSE": LINE,
    "_FILL_RECEIVER": LINE, "_OPEN_SUBSCRIPT": LINE, "_ATTRIBUTE_LINE": LINE, "_KEYED_FIELD": LINE,
    "_CODE_KEY": LINE, "_KEY_SPLIT": LINE, "_ROOT_SPLIT": LINE, "_BARE_CALL": LINE, "_PEER_FIRST_ARG": LINE,
    "_RECEIVER_PREFIX": LINE, "_CONTENT_TEST": LINE, "_ERROR_CONSTRUCTOR": LINE, "_EXIT_WORD": LINE,
    "_FORWARDED": LINE, "_RAW_ERROR_READ": LINE, "_WRAPPED_CAUSE": LINE, "_MEMBER_CHAIN_TEXT": LINE,
    "_QUOTE": LINE, "_MEMBER_WRITE": LINE, "_SETTER_WRITE": LINE, "_INSERT_WRITE": LINE,
    "_ASYNC_ITERATION": LINE, "_QUOTED_WORD": LINE, "_CASE_LABEL": LINE, "_OWN_CASE_LABEL": LINE,
    "_MEMBER_NAME": LINE, "_LITERAL_RETURN": LINE, "_PAREN": JOINED, "_LOG_OPEN": LINE,
    "_NAMED_DECL_ANY": JOINED, "_ASSIGNED_ROUTINE_ANY": JOINED, "_CALL_TAIL": LINE, "_CALL_LEAD": LINE,
    "_LEADING_DECL": LINE, "_ROUTINE_KEYWORD": LINE,
    "_BRACKET": JOINED, "_CUT_CHARS": JOINED, "_SPLIT_CHARS": JOINED, "_PARENS": LINE,
}
JOIN_ROWS = 30
# Every per-name pattern builder, and the bounded subject it is applied to.
TEMPLATES = {
    "_population_pattern": LINE, "_member_assign_pattern": LINE, "_variable_binding_pattern": LINE,
    "_record_head": LINE, "_struct_new_head": LINE, "_struct_block_head": LINE, "_dataclass_head": LINE,
    "_helper_signature_pattern": JOINED, "_whole_token_pattern": LINE, "_assigned_call_pattern": LINE,
    "_nearest_assignment_pattern": LINE, "_word_pattern": JOINED, "_responder_param_pattern": LINE,
    "_member_of_pattern": LINE, "_compared_member_pattern": LINE, "_switch_on_pattern": LINE,
    "_param_as_error_pattern": LINE,
}
NAMES = ("a" * 64, "_" * 64, "$" * 64, "Aa1" * 21 + "x")


def _section_names() -> set[str]:
    path = Path(importlib.import_module(MODULE).__file__)
    lines = path.read_text(encoding="utf-8").splitlines()
    begin = next((i for i, x in enumerate(lines, 1) if x.startswith(BEGIN)), None)
    end = next((i for i, x in enumerate(lines, 1) if x.startswith(END)), None)
    if begin is None or end is None:
        return set()
    tree = ast.parse("\n".join(lines))
    names: set[str] = set()
    for node in tree.body:
        if begin < node.lineno < end:
            names |= _assigned(node)
    return names


def _assigned(node: ast.stmt) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
    return {t.id for t in targets if isinstance(t, ast.Name)}


def discover_patterns() -> dict[str, re.Pattern[str]]:
    module = importlib.import_module(MODULE)
    section = _section_names()
    return {k: v for k, v in vars(module).items() if k in section and isinstance(v, re.Pattern)}


PATTERN_NAMES: tuple[str, ...] = tuple(sorted(discover_patterns()))
TEMPLATE_CASES: tuple[str, ...] = tuple(f"{b}|{i}" for b in sorted(TEMPLATES) for i in range(len(NAMES)))


def _bounded(subject: str, bound: str | None) -> str:
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    if bound == LINE:
        return subject[:MAX_SCAN_CHARS]
    if bound == JOINED:
        return subject[: MAX_SCAN_CHARS * JOIN_ROWS]
    return subject


def _pattern_for(case: str) -> tuple[re.Pattern[str] | None, str | None]:
    if "|" not in case:
        return discover_patterns().get(case), BOUNDED.get(case)
    builder, index = case.split("|")
    module = importlib.import_module(MODULE)
    build = getattr(module, builder, None)
    if build is None:
        return None, None
    return re.compile(build(NAMES[int(index)])), TEMPLATES[builder]


def _child_main(case: str, out_path: str) -> int:
    pattern, bound = _pattern_for(case)
    with open(out_path, "w", encoding="utf-8") as handle:
        def emit(record: dict) -> None:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if pattern is None:
            emit({"status": "missing", "name": case})
            return 1
        for input_name in INPUT_NAMES:
            subject = _bounded(lexgate.build_input(input_name), bound)
            emit({"status": "start", "input": input_name})
            emit({"status": "ok", "input": input_name, "ms": _measure_one(pattern, subject)})
    return 0


def _run_child(case: str) -> dict[str, float | None]:
    fd, out_path = tempfile.mkstemp(prefix="redos209r3_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run(
                [sys.executable, "-m", "tests.unit.test_0101_cwe209_r3_redos", "--child", case, out_path],
                cwd=AGENT_ROOT, capture_output=True, text=True, timeout=PROC_TIMEOUT_SEC * 2, check=False,
            )
        except subprocess.TimeoutExpired:
            pass
        results: dict[str, float | None] = {}
        with open(out_path, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                record = json.loads(raw)
                if record["status"] == "missing":
                    pytest.fail(f"{case!r} is not defined by {MODULE}")
                results[record["input"]] = record.get("ms")
    finally:
        os.unlink(out_path)
    return results


def _over_budget(timings: dict[str, float | None]) -> dict[str, float | None]:
    return {n: ms for n in INPUT_NAMES if (ms := timings.get(n)) is None or ms >= BUDGET_MS}


def test_section_discovery_is_not_vacuous() -> None:
    assert len(PATTERN_NAMES) >= MIN_PATTERNS, (
        f"{MODULE}: {len(PATTERN_NAMES)} patterns between the revision-3 banners ({list(PATTERN_NAMES)}); "
        f"the pinned floor is {MIN_PATTERNS}. Fix the discovery, do not lower the floor.")


def test_bounded_names_are_section_patterns() -> None:
    assert set(BOUNDED) <= set(PATTERN_NAMES), sorted(set(BOUNDED) - set(PATTERN_NAMES))


def test_every_template_builder_exists() -> None:
    module = importlib.import_module(MODULE)
    assert all(callable(getattr(module, b, None)) for b in TEMPLATES), [b for b in TEMPLATES if not hasattr(module, b)]


@pytest.mark.parametrize("pattern_name", PATTERN_NAMES)
def test_pattern_survives_adversarial_input(pattern_name: str) -> None:
    bad = _over_budget(_run_child(pattern_name))
    assert not bad, f"{pattern_name}: budget {BUDGET_MS:.1f} ms per {INPUT_BYTES // 1024} KB; over budget: {bad}"


@pytest.mark.parametrize("case", TEMPLATE_CASES)
def test_templated_pattern_survives_adversarial_names_and_input(case: str) -> None:
    bad = _over_budget(_run_child(case))
    assert not bad, f"{case}: budget {BUDGET_MS:.1f} ms per {INPUT_BYTES // 1024} KB; over budget: {bad}"


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <case> <out_path> is internal")
