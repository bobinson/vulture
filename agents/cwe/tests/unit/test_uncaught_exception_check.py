"""Tests for CWE-248 uncaught-exception detection skill."""


def test_fires_on_java_throws_exception(tmp_path):
    """Java method with `throws Exception` fires CWE-248."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void m() throws Exception {\n"
        "        foo();\n"
        "    }\n"
        "}\n"
    )
    from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception
    cwes = {x["category"] for x in check_uncaught_exception(str(tmp_path))["findings"]}
    assert "CWE-248" in cwes


def test_fires_on_python_bare_pass_except_exception(tmp_path):
    """Python except Exception with bare pass fires CWE-248."""
    f = tmp_path / "v.py"
    f.write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception
    cwes = {x["category"] for x in check_uncaught_exception(str(tmp_path))["findings"]}
    assert "CWE-248" in cwes


def test_no_fire_when_reraise_with_chain(tmp_path):
    """except Exception that re-raises with `from e` must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text(
        "class CustomError(Exception): pass\n"
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except Exception as e:\n"
        "        raise CustomError() from e\n"
    )
    from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception
    assert check_uncaught_exception(str(tmp_path))["findings"] == []


def test_no_fire_on_unrelated_python_code(tmp_path):
    """Python file without any exception handler must not crash and must not fire."""
    f = tmp_path / "v.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception
    assert check_uncaught_exception(str(tmp_path))["findings"] == []


def test_language_gate_go_no_fire(tmp_path):
    """Skill applies only to .java and .py — Go must NOT fire."""
    f = tmp_path / "v.go"
    f.write_text(
        "package m\n"
        "func run(x func()) {\n"
        "    defer func() { _ = recover() }()\n"
        "    x()\n"
        "}\n"
    )
    from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception
    assert check_uncaught_exception(str(tmp_path))["findings"] == []
