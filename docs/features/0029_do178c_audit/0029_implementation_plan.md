# DO-178C Compliance Auditor Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a DO-178C software assurance audit agent that statically checks source code against DO-178C/ED-12C objectives: dead code detection, MC/DC coverage gap analysis, recursion/malloc flagging, requirements traceability tag verification, and deterministic timing checks --- all configurable by Design Assurance Level (DAL A through E).

**Architecture:** New Python agent at `agents/do178c/` following the same pattern as existing agents (owasp, cwe, ssdf). 6 skills covering the key static-analysis objectives. DAL level is a config parameter that controls which skills run and what severity findings produce. Registered via one line in Go agent registry, one service block in docker-compose.

**Tech Stack:** Python 3.12+, shared audit_runner, FastAPI/SSE, pre-compiled regex patterns, AST analysis for recursion/malloc detection.

---

## File Structure

```
agents/do178c/
  do178c_agent/
    __init__.py
    agent.py              # run_audit: orchestrates via run_combined_audit
    config.py             # DAL definitions, ALL_CATEGORIES, AGENT_INFO, CONFIG_SCHEMA
    main.py               # FastAPI entry point via create_sse_app
    skills/
      __init__.py          # SKILL_MAP, SKILL_TOOLS exports
      SKILLS.md            # Skill documentation
      dead_code_check.py   # Unreachable branches, unused functions
      mcdc_coverage.py     # MC/DC gap analysis: missing coverage markers
      recursion_check.py   # Recursive calls, unbounded loops
      malloc_check.py      # Dynamic allocation in safety-critical paths
      traceability_check.py # Requirement tag verification (@requirement, // REQ-)
      timing_check.py      # Deterministic timing: sleep, wall-clock reads, unbounded I/O
  tests/
    unit/
      test_skills.py
    e2e/
      test_do178c_audit.py
  Dockerfile
  pyproject.toml
```

**Registration files (modify):**
- `backend/pkg/agentregistry/registry.go` --- add 1 line
- `docker-compose.yml` --- add 1 service block

---

## DAL Severity Mapping

Each DAL level determines which skills run and the default severity for findings:

| Skill | DAL A | DAL B | DAL C | DAL D | DAL E |
|-------|-------|-------|-------|-------|-------|
| dead_code | critical | critical | high | medium | skip |
| mcdc_coverage | critical | high | skip | skip | skip |
| recursion | critical | critical | high | skip | skip |
| malloc | critical | critical | high | medium | skip |
| traceability | critical | high | high | medium | skip |
| timing | critical | high | medium | skip | skip |

---

## Task 1: Project scaffolding and packaging

**Files:**
- Create: `agents/do178c/do178c_agent/__init__.py`
- Create: `agents/do178c/pyproject.toml`
- Create: `agents/do178c/Dockerfile`

- [ ] **Step 1: Create __init__.py**

```python
```

(Empty module marker)

- [ ] **Step 2: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "vulture-do178c-agent"
version = "0.1.0"
description = "DO-178C compliance audit agent for Vulture"
requires-python = ">=3.12"
dependencies = [
    "vulture-shared",
]

[tool.hatch.build.targets.wheel]
packages = ["do178c_agent"]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "httpx>=0.28.0",
    "anyio[trio]>=4.0.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.coverage.run]
source = ["do178c_agent"]
```

- [ ] **Step 3: Create Dockerfile**

```dockerfile
FROM vulture-agent-base:latest
COPY do178c/ /app/do178c/
RUN pip install --no-cache-dir /app/do178c
EXPOSE 28009
CMD ["sh", "-c", "uvicorn do178c_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28009}"]
```

- [ ] **Step 4: Create tests directory**

```bash
mkdir -p agents/do178c/tests/unit agents/do178c/tests/e2e
touch agents/do178c/tests/__init__.py agents/do178c/tests/unit/__init__.py agents/do178c/tests/e2e/__init__.py
```

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/
git commit -m "feat(do178c): project scaffolding and packaging"
```

---

## Task 2: Config and DAL definitions

**Files:**
- Create: `agents/do178c/do178c_agent/config.py`

- [ ] **Step 1: Write the failing test**

```python
# agents/do178c/tests/unit/test_config.py
from do178c_agent.config import (
    ALL_CATEGORIES,
    AGENT_INFO,
    CONFIG_SCHEMA,
    DAL_LEVELS,
    dal_severity,
    dal_skip,
)


def test_all_categories_has_six_skills():
    assert len(ALL_CATEGORIES) == 6
    assert "dead_code" in ALL_CATEGORIES
    assert "mcdc_coverage" in ALL_CATEGORIES
    assert "recursion" in ALL_CATEGORIES
    assert "malloc" in ALL_CATEGORIES
    assert "traceability" in ALL_CATEGORIES
    assert "timing" in ALL_CATEGORIES


def test_dal_levels():
    assert DAL_LEVELS == ["A", "B", "C", "D", "E"]


def test_dal_severity_returns_correct_level():
    assert dal_severity("A", "dead_code") == "critical"
    assert dal_severity("B", "mcdc_coverage") == "high"
    assert dal_severity("D", "dead_code") == "medium"


def test_dal_skip_returns_true_for_excluded():
    assert dal_skip("E", "dead_code") is True
    assert dal_skip("C", "mcdc_coverage") is True
    assert dal_skip("A", "dead_code") is False


def test_agent_info_has_required_fields():
    assert AGENT_INFO["type"] == "do178c"
    assert "name" in AGENT_INFO
    assert "config_schema" in AGENT_INFO


def test_config_schema_has_dal_and_categories():
    props = CONFIG_SCHEMA["properties"]
    assert "dal_level" in props
    assert "categories" in props
    assert props["dal_level"]["enum"] == ["A", "B", "C", "D", "E"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_config.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Write config.py**

```python
"""DO-178C agent configuration and DAL severity mapping."""

ALL_CATEGORIES = [
    "dead_code",
    "mcdc_coverage",
    "recursion",
    "malloc",
    "traceability",
    "timing",
]

DAL_LEVELS = ["A", "B", "C", "D", "E"]

# DAL -> skill -> severity. Missing entry = skip.
_DAL_MAP: dict[str, dict[str, str]] = {
    "A": {
        "dead_code": "critical",
        "mcdc_coverage": "critical",
        "recursion": "critical",
        "malloc": "critical",
        "traceability": "critical",
        "timing": "critical",
    },
    "B": {
        "dead_code": "critical",
        "mcdc_coverage": "high",
        "recursion": "critical",
        "malloc": "critical",
        "traceability": "high",
        "timing": "high",
    },
    "C": {
        "dead_code": "high",
        "recursion": "high",
        "malloc": "high",
        "traceability": "high",
        "timing": "medium",
    },
    "D": {
        "dead_code": "medium",
        "malloc": "medium",
        "traceability": "medium",
    },
    "E": {},
}


def dal_severity(dal: str, skill: str) -> str:
    """Return the severity for a skill at a given DAL level."""
    return _DAL_MAP.get(dal, {}).get(skill, "info")


def dal_skip(dal: str, skill: str) -> bool:
    """Return True if skill should be skipped at this DAL level."""
    return skill not in _DAL_MAP.get(dal, {})


CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "dal_level": {
            "type": "string",
            "enum": DAL_LEVELS,
            "default": "C",
            "description": "Design Assurance Level (A=catastrophic through E=no effect)",
        },
        "categories": {
            "type": "array",
            "items": {"type": "string", "enum": ALL_CATEGORIES},
            "default": ALL_CATEGORIES,
            "description": "DO-178C objective categories to audit",
        },
    },
}

AGENT_INFO = {
    "type": "do178c",
    "name": "DO-178C Compliance Auditor",
    "description": "Static analysis for DO-178C/ED-12C software assurance objectives. "
    "Configurable by Design Assurance Level (DAL A-E). Covers dead code, "
    "MC/DC coverage gaps, recursion, dynamic allocation, requirements "
    "traceability, and deterministic timing.",
    "config_schema": CONFIG_SCHEMA,
    "skills": ALL_CATEGORIES,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_config.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/config.py agents/do178c/tests/unit/test_config.py
git commit -m "feat(do178c): DAL config and severity mapping"
```

---

## Task 3: Dead code detection skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/dead_code_check.py`

- [ ] **Step 1: Write the failing test**

```python
# agents/do178c/tests/unit/test_skills.py (append or create)
import os
import tempfile
from pathlib import Path

from do178c_agent.skills.dead_code_check import check_dead_code


class TestDeadCodeCheck:
    def test_detects_unreachable_after_return(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def foo():\n    return 1\n    x = 2\n"
        )
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.dead_code.unreachable"

    def test_detects_unreachable_after_sys_exit(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import sys\ndef bar():\n    sys.exit(1)\n    cleanup()\n"
        )
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_if_true_dead_branch(self, tmp_path):
        (tmp_path / "app.go").write_text(
            "package main\nfunc f() {\n    if true {\n        return\n    }\n    unreachable()\n}\n"
        )
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert "dead_code" in result["findings"][0]["check_id"]

    def test_no_finding_for_clean_code(self, tmp_path):
        (tmp_path / "clean.py").write_text(
            "def foo():\n    x = 1\n    return x\n"
        )
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "test_app.py").write_text(
            "def foo():\n    return 1\n    x = 2\n"
        )
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestDeadCodeCheck -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write dead_code_check.py**

```python
"""Dead/deactivated code detection (DO-178C Table A-5, Obj 5)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Statements that terminate control flow -- code after these is unreachable.
_TERMINATOR_RE = re.compile(
    r"^\s*(?:return\b|sys\.exit\(|os\._exit\(|raise\b|panic\(|log\.Fatal)"
)

# Constant-true conditionals that make the else branch dead.
_CONST_TRUE_RE = re.compile(
    r"(?:if\s+(?:True|true|1)\s*[:{])|(?:if\s+true\s*\{)"
)

# Constant-false conditionals that make the if-body dead.
_CONST_FALSE_RE = re.compile(
    r"(?:if\s+(?:False|false|0)\s*[:{])|(?:if\s+false\s*\{)"
)


def check_dead_code(source_path: str) -> dict:
    """Detect dead/unreachable code after terminators and constant conditionals.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of dead code locations.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a single file for dead code patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    _check_unreachable(file_path, lines, findings)
    _check_constant_conditionals(file_path, lines, findings)


def _check_unreachable(
    file_path: Path, lines: list[str], findings: list[dict]
) -> None:
    """Flag code after return/raise/panic/sys.exit within the same block."""
    terminator_line = -1
    terminator_indent = -1
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or COMMENT_INDICATORS.match(stripped):
            continue
        indent = len(line) - len(stripped)
        # Reset tracking if we've moved to a different indentation scope.
        if indent <= terminator_indent and terminator_line >= 0:
            terminator_line = -1
            terminator_indent = -1
        if terminator_line >= 0 and indent > terminator_indent:
            findings.append({
                "severity": "high",
                "check_id": "do178c.dead_code.unreachable",
                "category": "dead_code",
                "title": "Unreachable code after terminator",
                "description": f"Code at line {i + 1} is unreachable after terminator at line {terminator_line + 1}",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Remove unreachable code or restructure control flow",
                "code_snippet": extract_snippet(lines, i + 1),
            })
            terminator_line = -1
            terminator_indent = -1
            continue
        if _TERMINATOR_RE.match(stripped):
            terminator_line = i
            terminator_indent = indent


def _check_constant_conditionals(
    file_path: Path, lines: list[str], findings: list[dict]
) -> None:
    """Flag if-true / if-false constant conditionals."""
    for i, line in enumerate(lines):
        if COMMENT_INDICATORS.match(line.lstrip()):
            continue
        if _CONST_TRUE_RE.search(line):
            findings.append({
                "severity": "medium",
                "check_id": "do178c.dead_code.const_true",
                "category": "dead_code",
                "title": "Constant-true conditional creates dead else branch",
                "description": f"Condition at line {i + 1} is always true",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Remove the conditional or replace with runtime check",
                "code_snippet": extract_snippet(lines, i + 1),
            })
        elif _CONST_FALSE_RE.search(line):
            findings.append({
                "severity": "medium",
                "check_id": "do178c.dead_code.const_false",
                "category": "dead_code",
                "title": "Constant-false conditional creates dead if-body",
                "description": f"Condition at line {i + 1} is always false",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Remove dead branch or replace with runtime check",
                "code_snippet": extract_snippet(lines, i + 1),
            })


check_dead_code_tool = function_tool(check_dead_code)
```

- [ ] **Step 4: Create skills/__init__.py**

```python
# agents/do178c/do178c_agent/skills/__init__.py
"""Empty until all skills are created. Populated in Task 9."""
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestDeadCodeCheck -v`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add agents/do178c/do178c_agent/skills/
git commit -m "feat(do178c): dead code detection skill"
```

---

## Task 4: MC/DC coverage gap skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/mcdc_coverage.py`

- [ ] **Step 1: Write the failing test**

```python
# append to agents/do178c/tests/unit/test_skills.py

from do178c_agent.skills.mcdc_coverage import check_mcdc_coverage


class TestMCDCCoverage:
    def test_detects_compound_condition_without_coverage_marker(self, tmp_path):
        (tmp_path / "logic.c").write_text(
            "void f() {\n    if (a && b || c) {\n        action();\n    }\n}\n"
        )
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.mcdc.compound_uncovered"

    def test_no_finding_for_simple_condition(self, tmp_path):
        (tmp_path / "simple.py").write_text(
            "if x > 0:\n    pass\n"
        )
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_detects_ternary_compound(self, tmp_path):
        (tmp_path / "tern.ts").write_text(
            "const v = (a && b) ? 1 : 0;\n"
        )
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_when_coverage_marker_present(self, tmp_path):
        (tmp_path / "covered.c").write_text(
            "// MCDC: verified\nvoid f() {\n    if (a && b) { action(); }\n}\n"
        )
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "test_logic.py").write_text(
            "if a and b or c:\n    pass\n"
        )
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestMCDCCoverage -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write mcdc_coverage.py**

```python
"""MC/DC coverage gap detection (DO-178C Table A-7, Obj 5-7)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Compound boolean: 2+ conditions joined by && / || / and / or.
_COMPOUND_RE = re.compile(
    r"(?:if|while|elif|else\s+if|assert|require|guard)\s*\("
    r"?[^;{}\n]*(?:&&|\|\||(?<!\w)and(?!\w)|(?<!\w)or(?!\w))[^;{}\n]*[){:]",
    re.IGNORECASE,
)

# Ternary with compound condition.
_TERNARY_COMPOUND_RE = re.compile(
    r"\([^)]*(?:&&|\|\|)[^)]*\)\s*\?",
)

# Coverage marker: any comment/annotation indicating MC/DC was verified.
_COVERAGE_MARKER_RE = re.compile(
    r"(?:MCDC|MC/DC|mcdc|modified.condition.decision).*(?:verified|covered|tested|ok)",
    re.IGNORECASE,
)


def check_mcdc_coverage(source_path: str) -> dict:
    """Detect compound boolean conditions without MC/DC coverage markers.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of uncovered compound conditions.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a file for compound conditions missing MC/DC coverage."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or COMMENT_INDICATORS.match(stripped):
            continue
        if not _COMPOUND_RE.search(line) and not _TERNARY_COMPOUND_RE.search(line):
            continue
        if _has_coverage_marker(lines, i):
            continue
        findings.append({
            "severity": "high",
            "check_id": "do178c.mcdc.compound_uncovered",
            "category": "mcdc_coverage",
            "title": "Compound condition without MC/DC coverage marker",
            "description": f"Compound boolean at line {i + 1} requires MC/DC test evidence",
            "file_path": str(file_path),
            "line_start": i + 1,
            "line_end": i + 1,
            "recommendation": "Add MC/DC test cases and annotate with '// MCDC: verified'",
            "code_snippet": extract_snippet(lines, i + 1),
        })


def _has_coverage_marker(lines: list[str], target: int) -> bool:
    """Check 3 lines above for a coverage annotation."""
    start = max(0, target - 3)
    context = "\n".join(lines[start:target])
    return bool(_COVERAGE_MARKER_RE.search(context))


check_mcdc_coverage_tool = function_tool(check_mcdc_coverage)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestMCDCCoverage -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/skills/mcdc_coverage.py agents/do178c/tests/unit/test_skills.py
git commit -m "feat(do178c): MC/DC coverage gap detection skill"
```

---

## Task 5: Recursion detection skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/recursion_check.py`

- [ ] **Step 1: Write the failing test**

```python
# append to agents/do178c/tests/unit/test_skills.py

from do178c_agent.skills.recursion_check import check_recursion


class TestRecursionCheck:
    def test_detects_direct_recursion_python(self, tmp_path):
        (tmp_path / "rec.py").write_text(
            "def factorial(n):\n    return n * factorial(n - 1)\n"
        )
        result = check_recursion(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.recursion.direct"

    def test_detects_direct_recursion_go(self, tmp_path):
        (tmp_path / "rec.go").write_text(
            "package main\nfunc fib(n int) int {\n    return fib(n-1) + fib(n-2)\n}\n"
        )
        result = check_recursion(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_unbounded_while_true(self, tmp_path):
        (tmp_path / "loop.py").write_text(
            "while True:\n    process()\n"
        )
        result = check_recursion(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert "unbounded" in result["findings"][0]["check_id"]

    def test_no_finding_for_bounded_loop(self, tmp_path):
        (tmp_path / "bounded.py").write_text(
            "for i in range(10):\n    process(i)\n"
        )
        result = check_recursion(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_no_finding_for_non_recursive_function(self, tmp_path):
        (tmp_path / "clean.py").write_text(
            "def add(a, b):\n    return a + b\n"
        )
        result = check_recursion(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestRecursionCheck -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write recursion_check.py**

```python
"""Recursion and unbounded loop detection (DO-178C 6.3.4.f)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Function definition patterns per language.
_FUNC_DEF_RE = re.compile(
    r"(?:def\s+(\w+)|func\s+(?:\([^)]*\)\s+)?(\w+)|function\s+(\w+))"
)

# Unbounded loop patterns.
_UNBOUNDED_LOOP_RE = re.compile(
    r"^\s*(?:while\s+(?:True|true|1)\s*[:{]|for\s*\(\s*;;\s*\)\s*\{|loop\s*\{)"
)


def check_recursion(source_path: str) -> dict:
    """Detect direct recursion and unbounded loops.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of recursion/loop issues.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a file for recursion and unbounded loops."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    _check_direct_recursion(file_path, lines, findings)
    _check_unbounded_loops(file_path, lines, findings)


def _check_direct_recursion(
    file_path: Path, lines: list[str], findings: list[dict]
) -> None:
    """Detect functions that call themselves."""
    current_func: str | None = None
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if COMMENT_INDICATORS.match(stripped):
            continue
        m = _FUNC_DEF_RE.search(line)
        if m:
            current_func = m.group(1) or m.group(2) or m.group(3)
            continue
        if current_func and re.search(rf"\b{re.escape(current_func)}\s*\(", stripped):
            findings.append({
                "severity": "critical",
                "check_id": "do178c.recursion.direct",
                "category": "recursion",
                "title": f"Direct recursion in '{current_func}'",
                "description": f"Function '{current_func}' calls itself at line {i + 1}",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Replace recursion with iteration or prove bounded depth",
                "code_snippet": extract_snippet(lines, i + 1),
            })


def _check_unbounded_loops(
    file_path: Path, lines: list[str], findings: list[dict]
) -> None:
    """Flag while-true and for(;;) loops."""
    for i, line in enumerate(lines):
        if _UNBOUNDED_LOOP_RE.match(line):
            findings.append({
                "severity": "high",
                "check_id": "do178c.recursion.unbounded_loop",
                "category": "recursion",
                "title": "Unbounded loop",
                "description": f"Potentially infinite loop at line {i + 1}",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Add explicit bound or termination proof",
                "code_snippet": extract_snippet(lines, i + 1),
            })


check_recursion_tool = function_tool(check_recursion)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestRecursionCheck -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/skills/recursion_check.py agents/do178c/tests/unit/test_skills.py
git commit -m "feat(do178c): recursion and unbounded loop detection"
```

---

## Task 6: Dynamic allocation (malloc) detection skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/malloc_check.py`

- [ ] **Step 1: Write the failing test**

```python
# append to agents/do178c/tests/unit/test_skills.py

from do178c_agent.skills.malloc_check import check_malloc


class TestMallocCheck:
    def test_detects_c_malloc(self, tmp_path):
        (tmp_path / "alloc.c").write_text(
            "void* buf = malloc(1024);\n"
        )
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.malloc.dynamic_alloc"

    def test_detects_python_append_in_loop(self, tmp_path):
        (tmp_path / "grow.py").write_text(
            "items = []\nfor x in data:\n    items.append(x)\n"
        )
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_go_make_slice(self, tmp_path):
        (tmp_path / "alloc.go").write_text(
            "package main\nfunc f() {\n    s := make([]byte, n)\n}\n"
        )
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_new_keyword(self, tmp_path):
        (tmp_path / "alloc.cpp").write_text(
            "int* p = new int[100];\n"
        )
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_for_stack_allocation(self, tmp_path):
        (tmp_path / "stack.c").write_text(
            "int buf[1024];\n"
        )
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestMallocCheck -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write malloc_check.py**

```python
"""Dynamic allocation detection (DO-178C 6.3.4.f, Table A-5 Obj 6)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

_ALLOC_RE = re.compile(
    r"\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(|\bfree\s*\("
    r"|\bnew\s+\w+[\[(]"
    r"|\bmake\s*\(\s*\[\s*\]"
    r"|\bappend\s*\("
    r"|\b(?:ArrayList|LinkedList|HashMap|vector)\s*<",
)


def check_malloc(source_path: str) -> dict:
    """Detect dynamic memory allocation in source code.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of dynamic allocation sites.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a file for dynamic allocation patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or COMMENT_INDICATORS.match(stripped):
            continue
        if _ALLOC_RE.search(line):
            findings.append({
                "severity": "high",
                "check_id": "do178c.malloc.dynamic_alloc",
                "category": "malloc",
                "title": "Dynamic memory allocation",
                "description": f"Dynamic allocation at line {i + 1}",
                "file_path": str(file_path),
                "line_start": i + 1,
                "line_end": i + 1,
                "recommendation": "Use static allocation or pre-allocated buffers for DAL A/B",
                "code_snippet": extract_snippet(lines, i + 1),
            })


check_malloc_tool = function_tool(check_malloc)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestMallocCheck -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/skills/malloc_check.py agents/do178c/tests/unit/test_skills.py
git commit -m "feat(do178c): dynamic allocation detection skill"
```

---

## Task 7: Requirements traceability skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/traceability_check.py`

- [ ] **Step 1: Write the failing test**

```python
# append to agents/do178c/tests/unit/test_skills.py

from do178c_agent.skills.traceability_check import check_traceability


class TestTraceabilityCheck:
    def test_detects_missing_requirement_tag(self, tmp_path):
        (tmp_path / "module.py").write_text(
            "def critical_function():\n    '''No requirement tag here.'''\n    pass\n"
        )
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.trace.missing_req_tag"

    def test_no_finding_when_tag_present(self, tmp_path):
        (tmp_path / "tagged.py").write_text(
            "# @requirement: REQ-042\ndef critical_function():\n    pass\n"
        )
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_accepts_req_dash_format(self, tmp_path):
        (tmp_path / "tagged.go").write_text(
            "// REQ-101: implements altitude hold\nfunc hold() {}\n"
        )
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_accepts_hlr_llr_tags(self, tmp_path):
        (tmp_path / "tagged.c").write_text(
            "/* HLR-007: sensor input validation */\nvoid validate() {}\n"
        )
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "test_module.py").write_text(
            "def untagged_function():\n    pass\n"
        )
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestTraceabilityCheck -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write traceability_check.py**

```python
"""Requirements traceability verification (DO-178C Table A-3, Obj 1-4)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# Requirement tags: @requirement, REQ-NNN, HLR-NNN, LLR-NNN, SRS-NNN.
_REQ_TAG_RE = re.compile(
    r"@requirement|REQ-\d+|HLR-\d+|LLR-\d+|SRS-\d+|REQUIREMENT",
    re.IGNORECASE,
)

# Function/method definitions across languages.
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:def\s+\w+|func\s+(?:\([^)]*\)\s+)?\w+|function\s+\w+|"
    r"(?:public|private|protected|static|async)\s+\w+\s+\w+\s*\(|"
    r"(?:void|int|bool|string|char|float|double)\s+\w+\s*\()"
)


def check_traceability(source_path: str) -> dict:
    """Verify functions have requirement traceability tags.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of functions missing requirement tags.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a file for functions missing requirement tags."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if not _FUNC_DEF_RE.match(line):
            continue
        if _has_req_tag(lines, i):
            continue
        func_name = _extract_func_name(line)
        findings.append({
            "severity": "high",
            "check_id": "do178c.trace.missing_req_tag",
            "category": "traceability",
            "title": f"Function '{func_name}' missing requirement traceability",
            "description": f"No REQ/HLR/LLR tag found near function at line {i + 1}",
            "file_path": str(file_path),
            "line_start": i + 1,
            "line_end": i + 1,
            "recommendation": "Add requirement tag: // REQ-NNN or # @requirement: REQ-NNN",
        })


def _has_req_tag(lines: list[str], func_line: int) -> bool:
    """Check 5 lines above and the function line itself for a requirement tag."""
    start = max(0, func_line - 5)
    context = "\n".join(lines[start:func_line + 1])
    return bool(_REQ_TAG_RE.search(context))


def _extract_func_name(line: str) -> str:
    """Extract function name from a definition line."""
    m = re.search(r"(?:def|func|function)\s+(\w+)", line)
    if m:
        return m.group(1)
    m = re.search(r"\s(\w+)\s*\(", line)
    return m.group(1) if m else "unknown"


check_traceability_tool = function_tool(check_traceability)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestTraceabilityCheck -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/skills/traceability_check.py agents/do178c/tests/unit/test_skills.py
git commit -m "feat(do178c): requirements traceability verification skill"
```

---

## Task 8: Timing determinism skill

**Files:**
- Create: `agents/do178c/do178c_agent/skills/timing_check.py`

- [ ] **Step 1: Write the failing test**

```python
# append to agents/do178c/tests/unit/test_skills.py

from do178c_agent.skills.timing_check import check_timing


class TestTimingCheck:
    def test_detects_sleep_call(self, tmp_path):
        (tmp_path / "delay.py").write_text(
            "import time\ntime.sleep(1)\n"
        )
        result = check_timing(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert "timing" in result["findings"][0]["check_id"]

    def test_detects_wall_clock_read(self, tmp_path):
        (tmp_path / "clock.go").write_text(
            "package main\nimport \"time\"\nfunc f() {\n    t := time.Now()\n}\n"
        )
        result = check_timing(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_network_io(self, tmp_path):
        (tmp_path / "net.py").write_text(
            "import requests\nresponse = requests.get('http://api')\n"
        )
        result = check_timing(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_for_deterministic_code(self, tmp_path):
        (tmp_path / "pure.py").write_text(
            "def add(a, b):\n    return a + b\n"
        )
        result = check_timing(str(tmp_path))
        assert len(result["findings"]) == 0

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "test_timing.py").write_text(
            "import time\ntime.sleep(5)\n"
        )
        result = check_timing(str(tmp_path))
        assert len(result["findings"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestTimingCheck -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Write timing_check.py**

```python
"""Deterministic timing analysis (DO-178C 6.3.4.f, Table A-6 Obj 6)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

_TIMING_RE = re.compile(
    r"time\.sleep\s*\(|time\.Now\s*\(|time\.time\s*\("
    r"|datetime\.now\s*\(|Date\.now\s*\("
    r"|Thread\.sleep\s*\(|Sleep\s*\("
    r"|usleep\s*\(|nanosleep\s*\("
    r"|setTimeout\s*\(|setInterval\s*\(",
)

_NETWORK_IO_RE = re.compile(
    r"requests\.(?:get|post|put|delete|patch)\s*\("
    r"|urllib\.request\.urlopen\s*\("
    r"|http\.(?:Get|Post|Do)\s*\("
    r"|fetch\s*\("
    r"|socket\.connect\s*\(",
)


def check_timing(source_path: str) -> dict:
    """Detect non-deterministic timing: sleeps, wall-clock reads, network I/O.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of timing-indeterminate operations.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a file for non-deterministic timing patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or COMMENT_INDICATORS.match(stripped):
            continue
        _check_line(file_path, line, i, lines, findings)


def _check_line(
    file_path: Path, line: str, idx: int, lines: list[str], findings: list[dict]
) -> None:
    """Check a single line for timing or I/O indeterminism."""
    if _TIMING_RE.search(line):
        findings.append({
            "severity": "medium",
            "check_id": "do178c.timing.non_deterministic",
            "category": "timing",
            "title": "Non-deterministic timing operation",
            "description": f"Sleep or wall-clock read at line {idx + 1}",
            "file_path": str(file_path),
            "line_start": idx + 1,
            "line_end": idx + 1,
            "recommendation": "Use monotonic clock or deterministic scheduling",
            "code_snippet": extract_snippet(lines, idx + 1),
        })
    elif _NETWORK_IO_RE.search(line):
        findings.append({
            "severity": "medium",
            "check_id": "do178c.timing.network_io",
            "category": "timing",
            "title": "Unbounded network I/O",
            "description": f"Network call with indeterminate latency at line {idx + 1}",
            "file_path": str(file_path),
            "line_start": idx + 1,
            "line_end": idx + 1,
            "recommendation": "Add timeout bounds or move to non-safety-critical partition",
            "code_snippet": extract_snippet(lines, idx + 1),
        })


check_timing_tool = function_tool(check_timing)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agents/do178c && python -m pytest tests/unit/test_skills.py::TestTimingCheck -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agents/do178c/do178c_agent/skills/timing_check.py agents/do178c/tests/unit/test_skills.py
git commit -m "feat(do178c): deterministic timing analysis skill"
```

---

## Task 9: Skills index, SKILLS.md, agent, and entry point

**Files:**
- Create: `agents/do178c/do178c_agent/skills/__init__.py` (overwrite placeholder)
- Create: `agents/do178c/do178c_agent/skills/SKILLS.md`
- Create: `agents/do178c/do178c_agent/agent.py`
- Create: `agents/do178c/do178c_agent/main.py`

- [ ] **Step 1: Write skills/__init__.py**

```python
"""DO-178C skill registry."""

from do178c_agent.skills.dead_code_check import check_dead_code, check_dead_code_tool
from do178c_agent.skills.mcdc_coverage import check_mcdc_coverage, check_mcdc_coverage_tool
from do178c_agent.skills.recursion_check import check_recursion, check_recursion_tool
from do178c_agent.skills.malloc_check import check_malloc, check_malloc_tool
from do178c_agent.skills.traceability_check import check_traceability, check_traceability_tool
from do178c_agent.skills.timing_check import check_timing, check_timing_tool

SKILL_MAP = {
    "dead_code": check_dead_code,
    "mcdc_coverage": check_mcdc_coverage,
    "recursion": check_recursion,
    "malloc": check_malloc,
    "traceability": check_traceability,
    "timing": check_timing,
}

SKILL_TOOLS = [
    check_dead_code_tool,
    check_mcdc_coverage_tool,
    check_recursion_tool,
    check_malloc_tool,
    check_traceability_tool,
    check_timing_tool,
]
```

- [ ] **Step 2: Write SKILLS.md**

```markdown
# DO-178C Compliance Auditor - Skills

Static analysis for RTCA DO-178C / EUROCAE ED-12C airborne software assurance.
All skills configurable by Design Assurance Level (DAL A through E).

## dead_code_check
- **Function**: `check_dead_code(source_path: str) -> dict`
- **Purpose**: Detects unreachable code after return/raise/panic and constant-true/false conditionals
- **DO-178C Ref**: Table A-5 Obj 5 (dead code elimination)
- **Severity**: DAL A/B=critical, C=high, D=medium, E=skip

## mcdc_coverage
- **Function**: `check_mcdc_coverage(source_path: str) -> dict`
- **Purpose**: Flags compound boolean conditions (&&, ||, and, or) without MC/DC coverage markers
- **DO-178C Ref**: Table A-7 Obj 5-7 (structural coverage)
- **Severity**: DAL A=critical, B=high, C-E=skip

## recursion_check
- **Function**: `check_recursion(source_path: str) -> dict`
- **Purpose**: Detects direct recursion and unbounded loops (while true, for(;;))
- **DO-178C Ref**: 6.3.4.f (stack usage analysis)
- **Severity**: DAL A/B=critical, C=high, D-E=skip

## malloc_check
- **Function**: `check_malloc(source_path: str) -> dict`
- **Purpose**: Flags dynamic allocation (malloc, new, make, append, container types)
- **DO-178C Ref**: 6.3.4.f, Table A-5 Obj 6 (resource usage)
- **Severity**: DAL A/B=critical, C=high, D=medium, E=skip

## traceability_check
- **Function**: `check_traceability(source_path: str) -> dict`
- **Purpose**: Verifies functions have requirement tags (@requirement, REQ-NNN, HLR-NNN, LLR-NNN)
- **DO-178C Ref**: Table A-3 Obj 1-4 (requirements traceability)
- **Severity**: DAL A=critical, B/C=high, D=medium, E=skip

## timing_check
- **Function**: `check_timing(source_path: str) -> dict`
- **Purpose**: Detects non-deterministic timing: sleep, wall-clock reads, unbounded network I/O
- **DO-178C Ref**: 6.3.4.f, Table A-6 Obj 6 (deterministic execution)
- **Severity**: DAL A=critical, B=high, C=medium, D-E=skip
```

- [ ] **Step 3: Write agent.py**

```python
"""DO-178C Compliance audit agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from do178c_agent.config import ALL_CATEGORIES, dal_skip, dal_severity
from do178c_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are a DO-178C Software Assurance Auditor. Analyze source code against
RTCA DO-178C/ED-12C objectives for the specified Design Assurance Level (DAL).
Focus on: dead/deactivated code, MC/DC structural coverage gaps, recursion and
unbounded loops, dynamic memory allocation, requirements traceability, and
deterministic timing. Report findings with severity appropriate to the DAL level,
affected file, DO-178C table/objective reference, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the DO-178C compliance audit and yield SSE events."""
    dal = config.get("dal_level", "C")
    requested = config.get("categories", ALL_CATEGORIES)

    # Filter categories by DAL — skip skills not applicable at this level.
    categories = [c for c in requested if not dal_skip(dal, c)]

    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "do178c", preloaded=preloaded, max_findings=max_f)

    use_llm_val = config.get("use_llm")
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="DO-178C objectives",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
    )
```

- [ ] **Step 4: Write main.py**

```python
"""DO-178C Compliance agent FastAPI application."""

from shared.transport.sse_app import create_sse_app

from do178c_agent.agent import run_audit
from do178c_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="do178c",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)
```

- [ ] **Step 5: Run full test suite**

Run: `cd agents/do178c && python -m pytest tests/unit/ -v`
Expected: PASS (all 37 tests: 7 config + 30 skill tests)

- [ ] **Step 6: Commit**

```bash
git add agents/do178c/
git commit -m "feat(do178c): agent entry point, skills index, SKILLS.md"
```

---

## Task 10: Agent registry and docker-compose registration

**Files:**
- Modify: `backend/pkg/agentregistry/registry.go` (add 1 line)
- Modify: `docker-compose.yml` (add 1 service block)

- [ ] **Step 1: Add registry entry**

In `backend/pkg/agentregistry/registry.go`, add to `AllAgents` slice after the discover entry:

```go
	{"do178c", "DO-178C Compliance Auditor", "28009", "do178c", "do178c_agent.main:app", "agent_do178c"},
```

- [ ] **Step 2: Add docker-compose service block**

Add after the `agent-discover` service block in `docker-compose.yml`:

```yaml
  agent-do178c:
    build:
      context: ./agents
      dockerfile: do178c/Dockerfile
    expose:
      - "${VULTURE_AGENT_DO178C_PORT:-28009}"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - OPENAI_BASE_URL=${OPENAI_BASE_URL}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - VULTURE_LLM_MODEL=${VULTURE_LLM_MODEL:-${VULTURE_LLM_MODEL_DEFAULT:-gpt-4o}}
      - VULTURE_USE_LLM=${VULTURE_USE_LLM:-false}
      - OLLAMA_API_BASE=${OLLAMA_API_BASE:-http://host.docker.internal:11434}
      - VULTURE_AGENT_PORT=${VULTURE_AGENT_DO178C_PORT:-28009}
      - VULTURE_BACKEND_URL=http://backend:${VULTURE_BACKEND_PORT:-28080}
      - VULTURE_LLM_CTX_SIZE=${VULTURE_LLM_CTX_SIZE:-}
      - GEMINI_API_KEY=${GEMINI_API_KEY:-}
      - VULTURE_LLM_MAX_OUTPUT_TOKENS=${VULTURE_LLM_MAX_OUTPUT_TOKENS:-}
      - VULTURE_LOOP_GLOBAL_LIMIT=${VULTURE_LOOP_GLOBAL_LIMIT:-}
      - OPENAI_AGENTS_DISABLE_TRACING=1
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:${VULTURE_AGENT_DO178C_PORT:-28009}/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 15s
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
    volumes:
      - source-cache:/tmp/sources:ro
      - ${VULTURE_SOURCE_DIR:-./}:/mnt/source:ro
    restart: unless-stopped
```

- [ ] **Step 3: Add backend env var for agent URL**

In `docker-compose.yml` backend environment section, add:

```yaml
      - VULTURE_AGENT_DO178C_URL=http://agent-do178c:${VULTURE_AGENT_DO178C_PORT:-28009}
```

And add to backend depends_on:

```yaml
      agent-do178c:
        condition: service_healthy
```

- [ ] **Step 4: Commit**

```bash
git add backend/pkg/agentregistry/registry.go docker-compose.yml
git commit -m "feat(do178c): register agent in backend and docker-compose"
```

---

## Task 11: E2E test

**Files:**
- Create: `agents/do178c/tests/e2e/test_do178c_audit.py`

- [ ] **Step 1: Write E2E test**

```python
"""E2E tests for DO-178C audit agent."""

import tempfile
from pathlib import Path

from do178c_agent.agent import run_audit


def _collect_events(events):
    """Collect all SSE events into a list."""
    return list(events)


def _extract_findings(events):
    """Extract finding events from SSE stream."""
    import json
    findings = []
    for evt in events:
        if '"findings"' in evt and "event: StateSnapshot" not in evt:
            continue
        if evt.startswith("data: "):
            try:
                data = json.loads(evt[6:])
                if "findings" in data:
                    findings.extend(data["findings"])
            except (json.JSONDecodeError, KeyError):
                pass
    return findings


class TestDO178CAuditE2E:
    def test_full_audit_default_dal_c(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def process():\n    return 1\n    dead_code()\n\n"
            "items = []\nfor x in range(10):\n    items.append(x)\n"
        )
        events = _collect_events(run_audit("run-1", str(tmp_path), {"dal_level": "C"}))
        assert any("RunStarted" in e for e in events)
        assert any("RunFinished" in e for e in events)
        assert any("dead_code" in e for e in events)

    def test_dal_e_produces_no_findings(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def process():\n    return 1\n    dead_code()\n"
        )
        events = _collect_events(run_audit("run-2", str(tmp_path), {"dal_level": "E"}))
        # DAL E skips all skills — only start/finish events
        finding_events = [e for e in events if "finding" in e.lower() and "StateDelta" in e]
        assert len(finding_events) == 0

    def test_dal_a_runs_all_skills(self, tmp_path):
        (tmp_path / "app.c").write_text(
            "void* buf = malloc(1024);\n"
            "int fact(int n) { return n * fact(n-1); }\n"
        )
        events = _collect_events(run_audit("run-3", str(tmp_path), {"dal_level": "A"}))
        event_text = "\n".join(events)
        assert "malloc" in event_text or "dynamic_alloc" in event_text
        assert "recursion" in event_text

    def test_category_filter(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "def f():\n    return 1\n    dead()\n"
        )
        events = _collect_events(
            run_audit("run-4", str(tmp_path), {"dal_level": "C", "categories": ["dead_code"]})
        )
        event_text = "\n".join(events)
        assert "dead_code" in event_text
        # Should not contain other categories
        assert "mcdc" not in event_text
        assert "recursion" not in event_text
```

- [ ] **Step 2: Run E2E test**

Run: `cd agents/do178c && python -m pytest tests/e2e/ -v`
Expected: PASS (4 tests)

- [ ] **Step 3: Commit**

```bash
git add agents/do178c/tests/e2e/
git commit -m "feat(do178c): E2E tests for full audit pipeline"
```

---

## Task 12: Feature documentation

**Files:**
- Create: `docs/features/0029_do178c_audit/0029_implementation_status.md`
- Create: `docs/features/0029_do178c_audit/0029_rollback_plan.md`

- [ ] **Step 1: Write implementation status**

```markdown
# 0029 DO-178C Audit Implementation Status

| Task | Component | Status |
|------|-----------|--------|
| 1 | Scaffolding + packaging | Done |
| 2 | Config + DAL mapping | Done |
| 3 | Dead code skill | Done |
| 4 | MC/DC coverage skill | Done |
| 5 | Recursion detection skill | Done |
| 6 | Malloc detection skill | Done |
| 7 | Traceability skill | Done |
| 8 | Timing skill | Done |
| 9 | Agent + entry point + SKILLS.md | Done |
| 10 | Registry + docker-compose | Done |
| 11 | E2E tests | Done |
| 12 | Documentation | Done |
```

- [ ] **Step 2: Write rollback plan**

```markdown
# 0029 DO-178C Audit Rollback Plan

## Strategy
The DO-178C agent is fully self-contained. Rollback requires 3 changes:

1. Remove `agents/do178c/` directory
2. Remove the registry entry from `backend/pkg/agentregistry/registry.go`
3. Remove the `agent-do178c` service block and backend env var from `docker-compose.yml`

## Commands

```bash
rm -rf agents/do178c/
# Edit registry.go: remove the {"do178c", ...} line
# Edit docker-compose.yml: remove agent-do178c block + backend env var
git add -A
git commit -m "revert: remove DO-178C audit agent (0029)"
```

No database migration rollback needed. No frontend changes to revert.
Frontend auto-discovers agents via `GET /api/agents` --- removing the agent makes it disappear.
```

- [ ] **Step 3: Commit**

```bash
git add docs/features/0029_do178c_audit/
git commit -m "docs(do178c): feature documentation and rollback plan"
```
