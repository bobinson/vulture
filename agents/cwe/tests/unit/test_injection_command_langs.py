"""Feature 0060 — cross-language OS command-execution coverage in the injection
skill (CWE-78). These sinks were previously (incorrectly) emitted as CWE-676 by
the dangerous_function skill; 0060 moves ownership here so nothing is lost when
dangerous_function narrows to memory-unsafe library functions.
"""


def _cwes(tmp_path):
    from cwe_agent.skills.injection_check import check_injection
    return {x["category"] for x in check_injection(str(tmp_path))["findings"]}


def test_java_runtime_exec_flagged_cwe78(tmp_path):
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void run(String cmd) throws Exception {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "    }\n"
        "}\n"
    )
    assert "CWE-78" in _cwes(tmp_path)


def test_java_processbuilder_flagged_cwe78(tmp_path):
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void run(String cmd) throws Exception {\n"
        "        new ProcessBuilder(cmd).start();\n"
        "    }\n"
        "}\n"
    )
    assert "CWE-78" in _cwes(tmp_path)


def test_php_shell_exec_flagged_cwe78(tmp_path):
    f = tmp_path / "v.php"
    f.write_text("<?php\nfunction run($cmd) { return shell_exec($cmd); }\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_php_passthru_flagged_cwe78(tmp_path):
    f = tmp_path / "v.php"
    f.write_text("<?php\nfunction run($cmd) { passthru($cmd); }\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_php_proc_open_flagged_cwe78(tmp_path):
    f = tmp_path / "v.php"
    f.write_text("<?php\nfunction run($cmd) { proc_open($cmd, [], $p); }\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_os_system_still_cwe78_regression(tmp_path):
    """Regression guard: os.system remains CWE-78 (was already covered)."""
    f = tmp_path / "v.py"
    f.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_java_method_named_exec_not_command(tmp_path):
    """A benign method call `foo.exec(x)` in Java must NOT be a CWE-78 command
    finding (only Runtime.getRuntime().exec / ProcessBuilder are shell sinks)."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    void run(Statement st, String q) throws Exception { st.exec(q); }\n"
        "}\n"
    )
    assert "CWE-78" not in _cwes(tmp_path)


# --- Feature 0060 deferred: bare PHP/Ruby system (language-scoped) + .cjs scan ---

def test_php_bare_system_flagged_cwe78(tmp_path):
    f = tmp_path / "v.php"
    f.write_text("<?php\nfunction run($cmd) { system($cmd); }\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_ruby_bare_system_flagged_cwe78(tmp_path):
    f = tmp_path / "v.rb"
    f.write_text("def run(cmd)\n  system(cmd)\nend\n")
    assert "CWE-78" in _cwes(tmp_path)


def test_python_local_system_not_flagged_cwe78(tmp_path):
    """Guard: bare system() is a shell sink only in PHP/Ruby (language-scoped)."""
    f = tmp_path / "v.py"
    f.write_text("def system(x):\n    return x + 1\nq = system(5)\n")
    assert "CWE-78" not in _cwes(tmp_path)


def test_cjs_eval_scanned_cwe94(tmp_path):
    """.cjs is now scanned (RED-1 H1); bare eval is CWE-94 code injection."""
    f = tmp_path / "a.cjs"
    f.write_text("function run(code) { return eval(code); }\n")
    assert "CWE-94" in _cwes(tmp_path)


# --- Audit fixes #1 (def FP) + #2 (static-arg suppression FN) ---

def test_ruby_def_system_definition_not_flagged(tmp_path):
    """Audit #1: a Ruby instance-method DEFINITION named system must not FP."""
    f = tmp_path / "v.rb"
    f.write_text("def system(cmd)\n  @cmd = cmd\nend\n")
    assert "CWE-78" not in _cwes(tmp_path)


def test_php_function_system_definition_not_flagged(tmp_path):
    """Audit #1: a PHP function DEFINITION named system must not FP."""
    f = tmp_path / "v.php"
    f.write_text("<?php\nfunction system($cmd) { return $cmd; }\n")
    assert "CWE-78" not in _cwes(tmp_path)


def test_php_shell_exec_static_arg_still_flagged(tmp_path):
    """Audit #2: a static-string shell_exec is still a real shell invocation."""
    f = tmp_path / "v.php"
    f.write_text('<?php\nfunction run() { return shell_exec("ls -la"); }\n')
    assert "CWE-78" in _cwes(tmp_path)


def test_java_runtime_exec_static_arg_still_flagged(tmp_path):
    """Audit #2: static-string Runtime.exec must not be silently suppressed."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        '    void run() throws Exception { Runtime.getRuntime().exec("ls -la"); }\n'
        "}\n"
    )
    assert "CWE-78" in _cwes(tmp_path)
