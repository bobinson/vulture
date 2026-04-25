"""Tests for CWE-676 / CWE-242 dangerous-function detection skill."""


def test_fires_on_c_strcpy(tmp_path):
    """C strcpy call fires CWE-676 (or CWE-242)."""
    f = tmp_path / "v.c"
    f.write_text(
        "#include <string.h>\n"
        "void f(char *buf, const char *src) { strcpy(buf, src); }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert cwes & {"CWE-676", "CWE-242"}


def test_fires_on_python_os_system(tmp_path):
    """Python os.system fires CWE-676/CWE-242."""
    f = tmp_path / "v.py"
    f.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert cwes & {"CWE-676", "CWE-242"}


def test_fires_on_java_runtime_exec(tmp_path):
    """Java Runtime.getRuntime().exec fires."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void run(String cmd) throws Exception {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "    }\n"
        "}\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert cwes & {"CWE-676", "CWE-242"}


def test_no_fire_with_c_strncpy_alternate(tmp_path):
    """C strncpy with explicit bound must NOT fire (bounded alternate)."""
    f = tmp_path / "v.c"
    f.write_text(
        "#include <string.h>\n"
        "void f(char *buf, const char *src) { strncpy(buf, src, sizeof(buf)); }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_no_fire_with_subprocess_run_list(tmp_path):
    """Python subprocess.run with list form (no shell) must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text(
        "import subprocess\n"
        "def run(cmd, arg):\n"
        "    subprocess.run([cmd, arg])\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


# --- VLT-4768 hardening: detector must skip comment lines -------------------
#
# The dangerous-function detector previously matched pattern names ANYWHERE,
# including inside Python `#` comments, Go `//` comments, and C-style block
# comments. That produced false positives whenever someone documented a fix
# in a comment that mentioned the dangerous API by name (e.g., explaining
# why a guard was added against `os.system()` style injection). Lines that
# are pure comments must not produce findings.

def test_no_fire_for_python_hash_comment(tmp_path):
    f = tmp_path / "doc.py"
    f.write_text(
        "# A malicious module string CAN contain Python source that the\n"
        "# interpreter would execute (e.g. \"os; os.system('rm -rf /')\")\n"
        "x = 1\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_no_fire_for_go_double_slash_comment(tmp_path):
    f = tmp_path / "doc.go"
    f.write_text(
        "package main\n"
        "// e.g. \"os; os.system('rm -rf /')\". Reject any non-conforming input.\n"
        "// CWE-676 marks system() as risky-by-design.\n"
        "func ok() int { return 1 }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_no_fire_for_c_block_comment(tmp_path):
    f = tmp_path / "doc.c"
    f.write_text(
        "/* Demonstrates strcpy() unsafety — see strncpy alternative below. */\n"
        "int ok(void) { return 0; }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_still_fires_after_comment_in_real_code(tmp_path):
    """Negative control: a comment should NOT silence a real call below it."""
    f = tmp_path / "v.py"
    f.write_text(
        "# We avoid os.system here normally, but...\n"
        "import os\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert cwes & {"CWE-676", "CWE-242"}, "real call after a comment must still fire"
