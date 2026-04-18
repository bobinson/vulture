"""Tests for CWE-369 divide-by-zero detection skill."""


def test_fires_on_c_divide_by_variable(tmp_path):
    """C divide by non-literal variable fires CWE-369."""
    f = tmp_path / "v.c"
    f.write_text("int main() { int a=1, b=2; int r = a / b; return r; }\n")
    from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
    cwes = {x["category"] for x in check_divide_by_zero(str(tmp_path))["findings"]}
    assert "CWE-369" in cwes


def test_fires_on_go_divide_by_variable(tmp_path):
    """Go divide by non-literal variable fires CWE-369."""
    f = tmp_path / "v.go"
    f.write_text("package m\nfunc f(a, b int) int { r := a / b; return r }\n")
    from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
    cwes = {x["category"] for x in check_divide_by_zero(str(tmp_path))["findings"]}
    assert "CWE-369" in cwes


def test_no_fire_with_safe_context_guard(tmp_path):
    """C divide guarded by `if (b != 0)` must NOT fire."""
    f = tmp_path / "v.c"
    f.write_text(
        "int main() { int a=1, b=2; int r = 0;\n"
        "    if (b != 0) { r = a / b; }\n"
        "    return r; }\n"
    )
    from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
    assert check_divide_by_zero(str(tmp_path))["findings"] == []


def test_language_gate_python_no_fire(tmp_path):
    """Python divide must NOT fire — ZeroDivisionError is expected."""
    f = tmp_path / "v.py"
    f.write_text("def f(a, b):\n    r = a / b\n    return r\n")
    from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
    assert check_divide_by_zero(str(tmp_path))["findings"] == []


def test_no_fire_with_literal_divisor(tmp_path):
    """Literal divisor (known nonzero) must NOT fire."""
    f = tmp_path / "v.c"
    f.write_text("int main() { int a=10; int r = a / 5; return r; }\n")
    from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
    assert check_divide_by_zero(str(tmp_path))["findings"] == []
