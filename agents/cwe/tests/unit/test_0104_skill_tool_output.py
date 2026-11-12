"""Feature 0104 (D-S (1)): an A2 member row's private stamp never reaches the model
through a skill TOOL.

Each A2 head stamps every member row of a file's hint-only group with ``_hint_group``, the
group's sink lines (``consume.stamp_member``): ``k`` rows each carry the ``k``-tuple. On the
audit path ``audit_runner`` folds the group and takes the stamp off, and ``_public_view`` keeps
every ``_``-prefixed key out of what it emits. The same skills are also the model's tools: an
agent passes its ``skill_tools`` (here the CWE agent's ``SKILL_TOOLS``) to ``run_combined_audit``,
whose generate phase hands them to the model as the ``Agent``'s tools, beside its own file tools.
The SDK hands the model the value a tool returns (a dict, stringified), so there each private
key, and each member's copy of the tuple, would reach the model -- for every agent alike.

* RED: every tool of ``SKILL_TOOLS``, taken from the ``Agent`` one LLM-on audit hands the model
  (``handed``: the shared suite's fake model notes the tools, the preflight probe off, the L5
  judge not asked), invoked as the SDK invokes it (``on_invoke_tool`` with a ``ToolContext``
  and the JSON arguments), on a neutral root holding ``shelf.js`` (six hint-only CWE-22 sinks)
  and ``crate.js`` (three hint-only CWE-78 sinks), returns no ``_``-prefixed key at any depth,
  and is otherwise its skill function's own answer. A tool may answer with a string; it is
  read as JSON (or as the ``str`` of a dict).
* PIN: the skill FUNCTIONS still stamp each member row: the audit path folds on the stamp.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from agents import FunctionTool
from agents.tool_context import ToolContext

from cwe_agent.skills import SKILL_MAP, SKILL_TOOLS
from cwe_agent.skills.injection_check import check_injection
from cwe_agent.skills.input_validation_check import check_input_validation
from shared import audit_runner, quote_store
from shared.ast._records import PARAM_HINT_ROLE
from shared.testing.isolation import isolate
from shared.tools.file_scanner import clear_caches
from tests import _ast_v1
from tests._neutral import neutral_dir
from tests.unit.test_0104_hint_rows import _heuristic

# The shared suite's fake model, loaded by file: its ``tests`` package is not ours.
_FAKE_LLM = Path(__file__).resolve().parents[3] / "shared" / "tests" / "_fake_llm.py"
_spec = importlib.util.spec_from_file_location("_0104_tool_fake_llm", _FAKE_LLM)
_fake_llm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fake_llm)

# The member stamp (A2): private, so no emit carries it.
GROUP = "_hint_group"
# Six hint-only CWE-22 sinks (lines 4, 8, ..., 24): one file's group of six members.
SHELF = """const fs = require("fs");

function readShelf(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function dropShelf(filePath) {
  fs.unlinkSync(filePath);
}

function tagShelf(filePath, label) {
  fs.appendFileSync(filePath, label);
}

function listShelf(fileName) {
  return fs.readdirSync(fileName);
}

function fillShelf(fileName, body) {
  fs.writeFileSync(fileName, body);
}

function clearShelf(fileName) {
  fs.rmSync(fileName);
}

module.exports = { readShelf, dropShelf, tagShelf, listShelf, fillShelf, clearShelf };
"""
# Three hint-only CWE-78 sinks (lines 4, 8, 12): the injection head's group.
CRATE = """const childProcess = require("child_process");

function packCrate(filePath) {
  childProcess.execSync("gzip " + filePath);
}

function listCrate(fileName) {
  childProcess.execSync("ls " + fileName);
}

function dropCrate(filePath) {
  childProcess.execSync("rm " + filePath);
}

module.exports = { packCrate, listCrate, dropCrate };
"""
FILES = {"shelf.js": SHELF, "crate.js": CRATE}
# Each A2 skill function, the check id of its group, the file and the group's sink lines.
MEMBERS = [
    pytest.param(check_input_validation, "cwe.input_validation.path_traversal", "shelf.js",
                 (4, 8, 12, 16, 20, 24), id="input_validation"),
    pytest.param(check_injection, "cwe.injection.command", "crate.js", (4, 8, 12),
                 id="injection"),
]
# The skill function each tool wraps, by the tool's name (the function's).
FUNCTIONS: dict[str, Callable[[str], dict[str, Any]]] = {
    skill.__name__: skill for skill in SKILL_MAP.values()
}
# The skills that flag ``FILES``, so the generate phase sends them to the model.
SKILLS = ("input_validation", "injection")


class _Recorder(_fake_llm.FakeLLMProvider):
    """The fake model (it finds nothing), noting each tool of the ``Agent`` it is handed."""

    def __init__(self) -> None:
        super().__init__(scripted=[])
        self.tools: dict[str, FunctionTool] = {}

    async def run(self, agent: Any, **kwargs: Any) -> Any:
        self.tools.update((tool.name, tool) for tool in agent.tools)
        return await super().run(agent, **kwargs)


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """``FILES`` under a neutral root (the skills skip test paths)."""
    path = neutral_dir(request)
    for name, text in FILES.items():
        (path / name).write_text(text, encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def handed(root: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, FunctionTool]:
    """The tools, by name, of the ``Agent`` the generate phase hands the model in one LLM-on
    audit of ``root`` given the CWE agent's ``SKILL_TOOLS``, isolated as
    ``_0104_sites.finalized`` isolates."""
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, tmp_path_factory.mktemp("tool0104_home"))
        patch.setattr(quote_store, "_table_ready", False)
        patch.setenv("VULTURE_LLM_PREFLIGHT", "off")
        recorder = _fake_llm.install_fake_runner(patch, _Recorder())
        list(audit_runner.run_combined_audit(
            run_id="0104-tool-output", source_path=str(root), categories=list(SKILLS),
            skill_map={name: SKILL_MAP[name] for name in SKILLS}, use_llm=True,
            validate_use_llm=False, skill_tools=SKILL_TOOLS, instructions="audit",
            model="gpt-4o",
        ))
    assert recorder.calls >= 1, "the LLM phase never asked the model"
    return recorder.tools


def _decoded(answer: Any) -> Any:
    """``answer``; a string answer read as JSON, else as the ``str`` of a Python literal."""
    if not isinstance(answer, str):
        return answer
    try:
        return json.loads(answer)
    except json.JSONDecodeError:
        return ast.literal_eval(answer)


def _tool(handed: dict[str, FunctionTool], name: str) -> FunctionTool:
    """The tool ``name`` the generate phase hands the model."""
    assert name in handed, f"the generate phase never hands the model {name}"
    return handed[name]


def _invoked(tool: FunctionTool, root: Path) -> Any:
    """What ``tool`` returns for ``source_path=root``, called as the SDK calls it: its
    ``on_invoke_tool`` with a ``ToolContext`` and the JSON arguments (``_decoded``)."""
    arguments = json.dumps({"source_path": str(root)})
    ctx = ToolContext(
        context=None, tool_name=tool.name, tool_call_id="call_0104", tool_arguments=arguments
    )
    clear_caches()
    return _decoded(asyncio.run(tool.on_invoke_tool(ctx, arguments)))


def _own(name: str, root: Path) -> dict[str, Any]:
    """The answer of the skill function the tool ``name`` wraps, on ``root``."""
    assert name in FUNCTIONS, f"tool {name} names no skill function"
    clear_caches()
    return FUNCTIONS[name](str(root))


def _plain(value: Any) -> Any:
    """``value`` as JSON reads it back (a tuple is a list), so a dict answer and a JSON-string
    answer compare alike, and the helpers below see only dicts, lists and scalars."""
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _members(value: Any) -> list[tuple[Any, Any]]:
    """``(key, item)`` of a dict, ``(index, item)`` of a list, nothing of a scalar."""
    if isinstance(value, dict):
        return list(value.items())
    return list(enumerate(value)) if isinstance(value, list) else []


def _private_keys(value: Any, where: str = "$") -> list[str]:
    """The path of every ``_``-prefixed key at any depth of the plain value ``value``."""
    found: list[str] = []
    for key, item in _members(value):
        path = f"{where}[{key!r}]"
        found += [path] if str(key).startswith("_") else []
        found += _private_keys(item, path)
    return found


def _public(value: Any) -> Any:
    """The plain value ``value`` without any ``_``-prefixed key, at any depth."""
    if isinstance(value, dict):
        return _public_dict(value)
    return [_public(item) for item in value] if isinstance(value, list) else value


def _public_dict(value: dict[str, Any]) -> dict[str, Any]:
    """``_public`` of a dict: its keys but the ``_``-prefixed ones, each value ``_public``."""
    return {key: _public(item) for key, item in value.items() if not key.startswith("_")}


@pytest.mark.parametrize("name", [tool.name for tool in SKILL_TOOLS])
def test_tool_output_carries_no_private_key(
    name: str, handed: dict[str, FunctionTool], root: Path
) -> None:
    """RED (finding #5): the model never sees a ``_``-prefixed key of a skill's rows, and sees
    every other key of them unchanged."""
    returned = _invoked(_tool(handed, name), root)
    assert isinstance(returned, Mapping), f"{name} returned {type(returned).__name__}"
    plain = _plain(returned)
    assert _private_keys(plain) == [], f"{name} hands private keys to the model"
    assert plain == _public(_plain(_own(name, root)))


@pytest.mark.parametrize(("skill", "check_id", "name", "sinks"), MEMBERS)
def test_skill_function_still_stamps_its_members(
    skill: Callable[[str], dict[str, Any]],
    check_id: str,
    name: str,
    sinks: tuple[int, ...],
    root: Path,
) -> None:
    """PIN: each member row the skill FUNCTION returns is a hint-only row of ``name`` and
    carries its group's sink lines under ``_hint_group`` (the audit path folds on them)."""
    clear_caches()
    rows = _ast_v1.rows_for(skill(str(root))["findings"], check_id)
    assert [(Path(r["file_path"]).name, r["line_start"]) for r in rows] == [
        (name, line) for line in sinks
    ]
    assert {_heuristic(r) for r in rows} == {PARAM_HINT_ROLE}
    assert [tuple(r.get(GROUP) or ()) for r in rows] == [sinks] * len(sinks)
