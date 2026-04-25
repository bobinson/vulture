"""Unit tests for DO-178C agent skills."""

import pytest

from shared.tools.file_scanner import clear_caches

from do178c_agent.skills.dead_code_check import check_dead_code
from do178c_agent.skills.mcdc_coverage import check_mcdc_coverage
from do178c_agent.skills.recursion_check import check_recursion
from do178c_agent.skills.malloc_check import check_malloc
from do178c_agent.skills.traceability_check import check_traceability
from do178c_agent.skills.timing_check import check_timing


@pytest.fixture(autouse=True)
def _clear(tmp_path):
    """Clear file scanner caches before each test."""
    clear_caches()
    yield
    clear_caches()


# =====================================================================
# Dead Code
# =====================================================================

class TestDeadCodeUnreachable:
    """Detect unreachable code after return/raise/panic."""

    def test_unreachable_after_return(self, tmp_path):
        code = "def foo():\n    return 1\n    x = 2\n"
        (tmp_path / "a.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.dead_code.unreachable"

    def test_unreachable_after_raise(self, tmp_path):
        code = "def bar():\n    raise ValueError()\n    y = 3\n"
        (tmp_path / "b.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.dead_code.unreachable"

    def test_unreachable_after_panic_go(self, tmp_path):
        code = "func run() {\n    panic(\"fail\")\n    x := 1\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_dead_code(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.dead_code.unreachable"

    def test_no_finding_for_clean_code(self, tmp_path):
        code = "def foo():\n    x = 1\n    return x\n"
        (tmp_path / "clean.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        unreachable = [f for f in result["findings"] if f["check_id"] == "do178c.dead_code.unreachable"]
        assert unreachable == []

    def test_skips_test_files(self, tmp_path):
        code = "def foo():\n    return 1\n    x = 2\n"
        (tmp_path / "test_a.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        assert result["findings"] == []


class TestDeadCodeConstConditional:
    """Detect constant-true and constant-false conditionals."""

    def test_const_true_python(self, tmp_path):
        code = "def f():\n    if True:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        const = [f for f in result["findings"] if "const_true" in f["check_id"]]
        assert len(const) >= 1

    def test_const_false_python(self, tmp_path):
        code = "def f():\n    if False:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        const = [f for f in result["findings"] if "const_false" in f["check_id"]]
        assert len(const) >= 1

    def test_const_true_go(self, tmp_path):
        code = "func f() {\n    if true {\n        x := 1\n    }\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_dead_code(str(tmp_path))
        const = [f for f in result["findings"] if "const_true" in f["check_id"]]
        assert len(const) >= 1

    def test_no_finding_for_variable_condition(self, tmp_path):
        code = "def f(x):\n    if x > 0:\n        pass\n"
        (tmp_path / "clean.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        const = [f for f in result["findings"] if "const" in f["check_id"]]
        assert const == []

    def test_skips_test_files_const(self, tmp_path):
        code = "def f():\n    if True:\n        pass\n"
        (tmp_path / "test_x.py").write_text(code)
        result = check_dead_code(str(tmp_path))
        assert result["findings"] == []


# =====================================================================
# MC/DC Coverage
# =====================================================================

class TestMCDCCoverage:
    """Detect compound booleans lacking MC/DC coverage."""

    def test_detects_compound_and_or(self, tmp_path):
        code = "def f(a, b):\n    if a and b:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.mcdc.compound_uncovered"

    def test_detects_logical_or(self, tmp_path):
        code = "def f(a, b):\n    while a or b:\n        break\n"
        (tmp_path / "a.py").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_compound_go(self, tmp_path):
        code = "func f(a bool, b bool) {\n    if a && b {\n        return\n    }\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_simple_condition(self, tmp_path):
        code = "def f(x):\n    if x:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert result["findings"] == []

    def test_skips_test_files(self, tmp_path):
        code = "def f(a, b):\n    if a and b:\n        pass\n"
        (tmp_path / "test_logic.py").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert result["findings"] == []


class TestMCDCMarker:
    """MC/DC marker suppresses findings."""

    def test_marker_suppresses(self, tmp_path):
        code = "def f(a, b):\n    # MCDC verified\n    if a and b:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_mcdc_coverage(str(tmp_path))
        assert result["findings"] == []


# =====================================================================
# Recursion
# =====================================================================

class TestRecursionDirect:
    """Detect direct recursion."""

    def test_detects_self_call_python(self, tmp_path):
        code = "def factorial(n):\n    return n * factorial(n - 1)\n"
        (tmp_path / "a.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert len(direct) >= 1

    def test_detects_self_call_go(self, tmp_path):
        code = "func fib(n int) int {\n    return fib(n-1) + fib(n-2)\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert len(direct) >= 1

    def test_detects_self_call_js(self, tmp_path):
        code = "function walk(node) {\n    walk(node.left);\n}\n"
        (tmp_path / "tree.js").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert len(direct) >= 1

    def test_no_finding_iterative(self, tmp_path):
        code = "def factorial(n):\n    result = 1\n    for i in range(1, n+1):\n        result *= i\n    return result\n"
        (tmp_path / "a.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert direct == []

    def test_skips_test_files(self, tmp_path):
        code = "def factorial(n):\n    return n * factorial(n - 1)\n"
        (tmp_path / "test_math.py").write_text(code)
        result = check_recursion(str(tmp_path))
        assert result["findings"] == []

    def test_no_fp_method_on_different_object(self, tmp_path):
        """Regression: self._thread.start() is NOT recursion of start()."""
        code = (
            "class Server:\n"
            "    def start(self):\n"
            "        self._thread = threading.Thread(target=self._run)\n"
            "        self._thread.start()\n"
        )
        (tmp_path / "srv.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert direct == [], f"false positive: {direct}"

    def test_no_fp_async_def_scope(self, tmp_path):
        """Regression: call to helper() inside async def must not be flagged as helper's recursion."""
        code = (
            "def _make_finding(title):\n"
            "    return {'title': title}\n"
            "\n"
            "async def _probe(client):\n"
            "    return _make_finding('test')\n"
        )
        (tmp_path / "prober.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert direct == [], f"false positive: {direct}"

    def test_self_dot_method_is_recursion(self, tmp_path):
        """self.process() inside def process(self) IS recursion."""
        code = (
            "class Worker:\n"
            "    def process(self):\n"
            "        if not self.done:\n"
            "            self.process()\n"
        )
        (tmp_path / "worker.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert len(direct) >= 1

    def test_detects_real_recursion_in_flatten(self, tmp_path):
        """_flatten_yaml calling itself IS real recursion."""
        code = (
            "def _flatten_yaml(data, prefix, env_vars):\n"
            "    for key, val in data.items():\n"
            "        if isinstance(val, dict):\n"
            "            _flatten_yaml(val, key, env_vars)\n"
        )
        (tmp_path / "parser.py").write_text(code)
        result = check_recursion(str(tmp_path))
        direct = [f for f in result["findings"] if "direct" in f["check_id"]]
        assert len(direct) >= 1


class TestUnboundedLoop:
    """Detect unbounded loops."""

    def test_while_true_python(self, tmp_path):
        code = "def serve():\n    while True:\n        pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_recursion(str(tmp_path))
        loops = [f for f in result["findings"] if "unbounded_loop" in f["check_id"]]
        assert len(loops) >= 1

    def test_for_ever_c(self, tmp_path):
        code = "void run() {\n    for(;;) {\n        do_work();\n    }\n}\n"
        (tmp_path / "main.c").write_text(code)
        result = check_recursion(str(tmp_path))
        loops = [f for f in result["findings"] if "unbounded_loop" in f["check_id"]]
        assert len(loops) >= 1

    def test_loop_rust(self, tmp_path):
        code = "fn main() {\n    loop {\n        break;\n    }\n}\n"
        (tmp_path / "main.rs").write_text(code)
        result = check_recursion(str(tmp_path))
        loops = [f for f in result["findings"] if "unbounded_loop" in f["check_id"]]
        assert len(loops) >= 1


# =====================================================================
# Malloc / Dynamic Allocation
# =====================================================================

class TestMalloc:
    """Detect dynamic memory allocation."""

    def test_detects_malloc_c(self, tmp_path):
        code = "void f() {\n    int *p = malloc(100);\n}\n"
        (tmp_path / "alloc.c").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.malloc.dynamic_alloc"

    def test_detects_new_keyword(self, tmp_path):
        code = "public class Foo {\n    Object o = new Object();\n}\n"
        (tmp_path / "Foo.java").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_go_make(self, tmp_path):
        code = "func f() {\n    s := make([]int, 10)\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_static_alloc(self, tmp_path):
        code = "int buffer[256];\nvoid f() {\n    buffer[0] = 1;\n}\n"
        (tmp_path / "static.c").write_text(code)
        result = check_malloc(str(tmp_path))
        assert result["findings"] == []

    def test_skips_test_files(self, tmp_path):
        code = "void f() {\n    int *p = malloc(100);\n}\n"
        (tmp_path / "test_alloc.c").write_text(code)
        result = check_malloc(str(tmp_path))
        assert result["findings"] == []

    # --- VLT-4421 hardening: Go-specific append() pattern must not fire on
    # other languages. Python `list.append()` is the most common operation
    # in the language and must NOT be classified as DO-178C dynamic
    # allocation; the Go pattern is meant for Go's `append([]T, x)` /
    # `make([]T, n)` semantics only.

    def test_no_finding_for_python_list_append(self, tmp_path):
        code = (
            "def collect(items):\n"
            "    out = []\n"
            "    for x in items:\n"
            "        out.append(x)\n"          # Python list.append — NOT heap alloc
            "    return out\n"
        )
        (tmp_path / "v.py").write_text(code)
        result = check_malloc(str(tmp_path))
        assert result["findings"] == [], (
            f"Python list.append must not trigger DO-178C malloc finding, got: {result['findings']}"
        )

    def test_no_finding_for_javascript_array_append(self, tmp_path):
        # JS doesn't have an `append(` method on arrays out of the box, but
        # users define `.append()` on custom classes. The Go pattern must
        # not match in `.js`/`.ts` files either.
        code = "function add(arr, x){\n    arr.append(x);\n}\n"
        (tmp_path / "v.js").write_text(code)
        result = check_malloc(str(tmp_path))
        assert result["findings"] == []

    def test_go_append_still_fires(self, tmp_path):
        code = (
            "package main\n"
            "func collect(in []int) []int {\n"
            "    out := []int{}\n"
            "    for _, x := range in {\n"
            "        out = append(out, x)\n"   # Go append — IS dynamic alloc
            "    }\n"
            "    return out\n"
            "}\n"
        )
        (tmp_path / "main.go").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1, "Go `append(out, x)` must still fire"
        assert result["findings"][0]["category"] == "malloc"

    def test_python_C_extension_calls_still_fire_in_C_files(self, tmp_path):
        # If someone writes a .c file with Python C-extension code that
        # actually calls malloc(), the C pattern must still fire (the
        # language gate only narrows the *Go-flavoured* pattern).
        code = (
            "#include <stdlib.h>\n"
            "void f() {\n"
            "    char *buf = malloc(64);\n"
            "}\n"
        )
        (tmp_path / "ext.c").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1


class TestMallocContainers:
    """Detect dynamic containers."""

    def test_detects_arraylist(self, tmp_path):
        code = "public class Foo {\n    List<String> l = new ArrayList<String>();\n}\n"
        (tmp_path / "Foo.java").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_vector(self, tmp_path):
        code = "void f() {\n    vector<int> v;\n}\n"
        (tmp_path / "main.cpp").write_text(code)
        result = check_malloc(str(tmp_path))
        assert len(result["findings"]) >= 1


# =====================================================================
# Traceability
# =====================================================================

class TestTraceability:
    """Detect functions missing requirement traceability tags."""

    def test_detects_missing_tag_python(self, tmp_path):
        code = "def process():\n    pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["check_id"] == "do178c.trace.missing_req_tag"

    def test_detects_missing_tag_go(self, tmp_path):
        code = "func handle() {\n    return\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_detects_missing_tag_js(self, tmp_path):
        code = "function render() {\n    return null;\n}\n"
        (tmp_path / "app.js").write_text(code)
        result = check_traceability(str(tmp_path))
        assert len(result["findings"]) >= 1

    def test_no_finding_with_req_tag(self, tmp_path):
        code = "# REQ-001: process data\ndef process():\n    pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_traceability(str(tmp_path))
        assert result["findings"] == []

    def test_skips_test_files(self, tmp_path):
        code = "def process():\n    pass\n"
        (tmp_path / "test_proc.py").write_text(code)
        result = check_traceability(str(tmp_path))
        assert result["findings"] == []


class TestTraceabilityTags:
    """Various requirement tag formats are recognized."""

    def test_hlr_tag(self, tmp_path):
        code = "# HLR-042: high-level req\ndef compute():\n    pass\n"
        (tmp_path / "a.py").write_text(code)
        result = check_traceability(str(tmp_path))
        assert result["findings"] == []

    def test_srs_tag(self, tmp_path):
        code = "// SRS-007: safety req\nfunc run() {\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_traceability(str(tmp_path))
        assert result["findings"] == []


# =====================================================================
# Timing
# =====================================================================

class TestTimingNondeterministic:
    """Detect non-deterministic timing calls."""

    def test_detects_time_sleep(self, tmp_path):
        code = "import time\ndef wait():\n    time.sleep(1)\n"
        (tmp_path / "a.py").write_text(code)
        result = check_timing(str(tmp_path))
        timing = [f for f in result["findings"] if "nondeterministic" in f["check_id"]]
        assert len(timing) >= 1

    def test_detects_datetime_now(self, tmp_path):
        code = "from datetime import datetime\ndef now():\n    return datetime.now()\n"
        (tmp_path / "a.py").write_text(code)
        result = check_timing(str(tmp_path))
        timing = [f for f in result["findings"] if "nondeterministic" in f["check_id"]]
        assert len(timing) >= 1

    def test_detects_set_timeout_js(self, tmp_path):
        code = "function delay() {\n    setTimeout(() => {}, 1000);\n}\n"
        (tmp_path / "app.js").write_text(code)
        result = check_timing(str(tmp_path))
        timing = [f for f in result["findings"] if "nondeterministic" in f["check_id"]]
        assert len(timing) >= 1

    def test_no_finding_deterministic(self, tmp_path):
        code = "def compute(x):\n    return x * 2\n"
        (tmp_path / "a.py").write_text(code)
        result = check_timing(str(tmp_path))
        assert result["findings"] == []

    def test_skips_test_files(self, tmp_path):
        code = "import time\ndef wait():\n    time.sleep(1)\n"
        (tmp_path / "test_wait.py").write_text(code)
        result = check_timing(str(tmp_path))
        assert result["findings"] == []


class TestTimingUnboundedIO:
    """Detect unbounded network I/O."""

    def test_detects_requests_get(self, tmp_path):
        code = "import requests\ndef fetch():\n    requests.get('http://example.com')\n"
        (tmp_path / "a.py").write_text(code)
        result = check_timing(str(tmp_path))
        io_f = [f for f in result["findings"] if "unbounded_io" in f["check_id"]]
        assert len(io_f) >= 1

    def test_detects_fetch_js(self, tmp_path):
        code = "async function load() {\n    await fetch('/api/data');\n}\n"
        (tmp_path / "app.js").write_text(code)
        result = check_timing(str(tmp_path))
        io_f = [f for f in result["findings"] if "unbounded_io" in f["check_id"]]
        assert len(io_f) >= 1

    def test_detects_http_get_go(self, tmp_path):
        code = "func f() {\n    resp, _ := http.Get(\"http://example.com\")\n}\n"
        (tmp_path / "main.go").write_text(code)
        result = check_timing(str(tmp_path))
        io_f = [f for f in result["findings"] if "unbounded_io" in f["check_id"]]
        assert len(io_f) >= 1
