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


def test_os_system_not_owned_by_dangerous_function(tmp_path):
    """Feature 0060: os.system is OS command-exec (CWE-78) — owned by the
    injection skill, NOT dangerous_function. Ceding it removes the historical
    CWE-676/CWE-78 double-report. (Injection coverage is verified in
    test_injection_command_langs.py.)"""
    f = tmp_path / "v.py"
    f.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_java_runtime_exec_not_owned_by_dangerous_function(tmp_path):
    """Feature 0060: Runtime.getRuntime().exec is OS command-exec (CWE-78) —
    owned by the injection skill after 0060, not dangerous_function."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void run(String cmd) throws Exception {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "    }\n"
        "}\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


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
    """Negative control: a comment should NOT silence a real call below it.
    (0060: uses a retained C sink, since exec/os.system moved to injection.)"""
    f = tmp_path / "v.c"
    f.write_text(
        "#include <string.h>\n"
        "// We avoid strcpy here normally, but...\n"
        "void f(char *b, const char *s) { strcpy(b, s); }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert cwes & {"CWE-676", "CWE-242"}, "real call after a comment must still fire"


# --- Feature 0060: language-aware narrowing (memory-unsafe systems langs) ---
# dangerous_function now flags ONLY inherently-dangerous *library* functions in
# C/C++/Go/Rust. Execution sinks (eval/exec/os.system/os.popen) are ceded to the
# injection skill (CWE-78/CWE-94), which already handles them with a receiver-
# boundary that excludes method calls like RegExp.exec()/pipeline.exec().

def test_js_regex_exec_not_flagged(tmp_path):
    """RegExp.prototype.exec() is not a dangerous function (idattestor VLT-1038)."""
    f = tmp_path / "a.ts"
    f.write_text("const re = /x/;\nexport function f(s: string) { return re.exec(s); }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_redis_multi_exec_not_flagged(tmp_path):
    """ioredis pipeline .exec() is a transaction commit (VLT-1037/1039/1043)."""
    f = tmp_path / "a.ts"
    f.write_text("export async function f(multi: any) { return await multi.exec(); }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_python_bare_exec_ceded_to_injection(tmp_path):
    """Bare exec()/eval() is code-injection (CWE-94), owned by injection after
    0060; dangerous_function no longer emits for it."""
    f = tmp_path / "v.py"
    f.write_text("def run(code):\n    exec(code)\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_c_string_name_not_flagged_in_js_file(tmp_path):
    """Language scoping: a C string-handling name defined in a JS file is not a C sink."""
    f = tmp_path / "a.js"
    f.write_text("function strcpy(a, b) { return a + b; }\nconst z = strcpy('x', 'y');\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_go_unsafe_pointer_flagged(tmp_path):
    """Go unsafe.Pointer is a memory-unsafe primitive (CWE-676)."""
    f = tmp_path / "v.go"
    f.write_text(
        "package main\n"
        'import "unsafe"\n'
        "func f(p *int) uintptr { return uintptr(unsafe.Pointer(p)) }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-676" in cwes


def test_rust_transmute_flagged(tmp_path):
    """Rust std::mem::transmute is inherently dangerous (CWE-676)."""
    f = tmp_path / "v.rs"
    f.write_text("fn f(x: u32) -> i32 { unsafe { std::mem::transmute(x) } }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-676" in cwes


def test_rust_get_unchecked_flagged(tmp_path):
    """Rust slice::get_unchecked bypasses bounds checking (CWE-676)."""
    f = tmp_path / "v.rs"
    f.write_text("fn f(v: &[u8], i: usize) -> u8 { unsafe { *v.get_unchecked(i) } }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-676" in cwes


def test_gets_still_flags_242_in_c(tmp_path):
    """C gets() has no safe bound — CWE-242, preserved."""
    f = tmp_path / "v.c"
    f.write_text("#include <stdio.h>\nvoid f(char *b) { gets(b); }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-242" in cwes


def test_rust_transmute_not_flagged_in_python_file(tmp_path):
    """Language scoping: 'transmute(' in a .py file is not a Rust sink."""
    f = tmp_path / "v.py"
    f.write_text("def transmute(x):\n    return x\nq = transmute(5)\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


# --- Feature 0060 deferred P1 items: extension coverage, kill-switch, def-skip ---

def test_objc_strcpy_flagged_676(tmp_path):
    """Objective-C (.m) is C-family — strcpy is CWE-676 (RED-1 H9)."""
    f = tmp_path / "v.m"
    f.write_text("#import <string.h>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-676" in cwes


def test_rust_fn_named_transmute_definition_not_flagged(tmp_path):
    """A user function DEFINITION named transmute must not fire (RED-2 H1)."""
    f = tmp_path / "v.rs"
    f.write_text("fn transmute(x: u32) -> i32 {\n    x as i32\n}\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    assert check_dangerous_function(str(tmp_path))["findings"] == []


def test_disable_kill_switch(tmp_path, monkeypatch):
    """VULTURE_CWE_DISABLE_DANGEROUS_FN=true disables the skill (R13)."""
    f = tmp_path / "v.c"
    f.write_text("void f(char *b, const char *s){ strcpy(b, s); }\n")
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    monkeypatch.setenv("VULTURE_CWE_DISABLE_DANGEROUS_FN", "true")
    assert check_dangerous_function(str(tmp_path))["findings"] == []
    monkeypatch.setenv("VULTURE_CWE_DISABLE_DANGEROUS_FN", "false")
    assert check_dangerous_function(str(tmp_path))["findings"] != []


def test_go_unsafe_slice_flagged_676(tmp_path):
    """Audit #4: Go 1.17+ unsafe.Slice/Add are memory-unsafe primitives (CWE-676)."""
    f = tmp_path / "v.go"
    f.write_text(
        "package sample\n"
        'import "unsafe"\n'
        "func f(p *byte, n int) []byte { return unsafe.Slice(p, n) }\n"
    )
    from cwe_agent.skills.dangerous_function_check import check_dangerous_function
    cwes = {x["category"] for x in check_dangerous_function(str(tmp_path))["findings"]}
    assert "CWE-676" in cwes
