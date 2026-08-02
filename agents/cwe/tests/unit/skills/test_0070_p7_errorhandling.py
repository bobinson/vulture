"""Feature 0070 P7 — error-handling detection group.

Covers the six reviewed backlog items owned by
``error_handling_check.py`` / ``uncaught_exception_check.py``:

* CWE-280 — permission-typed empty handler (child of CWE-390, REPLACES it)
* CWE-484 — omitted break in a switch
* CWE-397 — declaration/raise of a generic exception (new arms)
* CWE-396 — catch of a generic exception TYPE (split out of CWE-755)
* CWE-394 — HTTP response consumed without checking the status
* CWE-382 — ``System.exit()`` inside a container-managed component

Every rule gets a positive AND a minimally-different clean twin. Row-stacking
invariants (P5: skill findings are not deduplicated against each other) are
asserted explicitly, because the parent detector fires on the same line.
"""

import pytest

from cwe_agent.skills.error_handling_check import check_error_handling
from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception


def _cats(source_dir, checker=check_error_handling) -> list[str]:
    """Return the emitted category list (with duplicates) for a tree."""
    return [f["category"] for f in checker(str(source_dir))["findings"]]


def _write(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(body)
    return path


# ── CWE-280: permission-typed empty handler (item 56) ─────────────────
class TestPermissionHandling:
    def test_python_permission_swallowed_fires(self, tmp_path):
        _write(tmp_path, "chmodder.py", (
            "def apply(p):\n"
            "    try:\n"
            "        do_chmod(p)\n"
            "    except PermissionError:\n"
            "        pass\n"
        ))
        assert "CWE-280" in _cats(tmp_path)

    def test_python_tuple_handler_fires(self, tmp_path):
        """`except (OSError, PermissionError):` — the parent 390 predicate
        cannot match the tuple form, so the 280 branch widens for itself."""
        _write(tmp_path, "chmodder.py", (
            "def apply(p):\n"
            "    try:\n"
            "        do_chmod(p)\n"
            "    except (OSError, PermissionError):\n"
            "        pass\n"
        ))
        assert "CWE-280" in _cats(tmp_path)

    def test_java_security_exception_swallowed_fires(self, tmp_path):
        _write(tmp_path, "Guard.java", (
            "class Guard {\n"
            "  void run() {\n"
            "    try { act(); } catch (SecurityException e) {}\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-280" in _cats(tmp_path)

    def test_replaces_parent_390_row(self, tmp_path):
        """P5: the child must SUPPRESS the parent on the same line."""
        _write(tmp_path, "chmodder.py", (
            "def apply(p):\n"
            "    try:\n"
            "        do_chmod(p)\n"
            "    except PermissionError:\n"
            "        pass\n"
        ))
        cats = _cats(tmp_path)
        assert cats.count("CWE-280") == 1
        assert "CWE-390" not in cats

    def test_handled_permission_error_clean(self, tmp_path):
        """Clean twin: the handler body records the failure."""
        _write(tmp_path, "chmodder.py", (
            "def apply(p):\n"
            "    try:\n"
            "        do_chmod(p)\n"
            "    except PermissionError as exc:\n"
            "        report(exc)\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-280" not in cats
        assert "CWE-390" not in cats

    def test_non_permission_empty_handler_stays_390(self, tmp_path):
        _write(tmp_path, "reader.py", (
            "def load(p):\n"
            "    try:\n"
            "        read(p)\n"
            "    except ValueError:\n"
            "        pass\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-390" in cats
        assert "CWE-280" not in cats


# ── CWE-484: omitted break in switch (item 57) ────────────────────────
class TestOmittedBreak:
    def test_c_fallthrough_fires(self, tmp_path):
        _write(tmp_path, "dispatch.c", (
            "int route(int op) {\n"
            "  switch (op) {\n"
            "    case 1:\n"
            "      grant(op);\n"
            "    case 2:\n"
            "      deny(op);\n"
            "      break;\n"
            "    default:\n"
            "      break;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" in _cats(tmp_path)

    def test_java_fallthrough_fires(self, tmp_path):
        _write(tmp_path, "Router.java", (
            "class Router {\n"
            "  int route(int op) {\n"
            "    switch (op) {\n"
            "      case 1:\n"
            "        grant(op);\n"
            "      case 2:\n"
            "        return deny(op);\n"
            "    }\n"
            "    return 0;\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-484" in _cats(tmp_path)

    def test_break_terminated_clean(self, tmp_path):
        """Clean twin — differs from the C positive by one `break;`."""
        _write(tmp_path, "dispatch.c", (
            "int route(int op) {\n"
            "  switch (op) {\n"
            "    case 1:\n"
            "      grant(op);\n"
            "      break;\n"
            "    case 2:\n"
            "      deny(op);\n"
            "      break;\n"
            "    default:\n"
            "      break;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    def test_stacked_labels_clean(self, tmp_path):
        _write(tmp_path, "dispatch.c", (
            "int route(int op) {\n"
            "  switch (op) {\n"
            "    case 1:\n"
            "    case 2:\n"
            "      deny(op);\n"
            "      break;\n"
            "    default:\n"
            "      break;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    @pytest.mark.parametrize("marker", [
        "/* fallthrough */",
        "// falls through",
        "/* FALLTHRU */",
        "[[fallthrough]];",
    ])
    def test_explicit_fallthrough_marker_clean(self, tmp_path, marker):
        _write(tmp_path, "dispatch.c", (
            "int route(int op) {\n"
            "  switch (op) {\n"
            "    case 1:\n"
            "      grant(op);\n"
            f"      {marker}\n"
            "    case 2:\n"
            "      deny(op);\n"
            "      break;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    def test_scoped_enumerator_label_clean(self, tmp_path):
        """`case Color::Red:` must not be mis-split at `Color:`, which would
        leave `:Red:` as a non-empty body and read as a fallthrough."""
        _write(tmp_path, "paint.cpp", (
            "int pick(Color c) {\n"
            "  switch (c) {\n"
            "    case Color::Red:\n"
            "      return 1;\n"
            "    case Color::Blue:\n"
            "      return 2;\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    def test_case_label_inside_string_literal_clean(self, tmp_path):
        _write(tmp_path, "help.c", (
            "const char *usage(void) {\n"
            "  return \"switch (x) { case 1: help(); case 2: }\";\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    def test_go_switch_excluded(self, tmp_path):
        """Go has no implicit fallthrough — the rule must never fire there."""
        _write(tmp_path, "route.go", (
            "package m\n"
            "func route(op int) int {\n"
            "  switch (op) {\n"
            "  case 1:\n"
            "    grant(op)\n"
            "  case 2:\n"
            "    deny(op)\n"
            "  }\n"
            "  return 0\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)

    def test_last_case_needs_no_terminator(self, tmp_path):
        _write(tmp_path, "dispatch.c", (
            "int route(int op) {\n"
            "  switch (op) {\n"
            "    case 1:\n"
            "      grant(op);\n"
            "      break;\n"
            "    default:\n"
            "      deny(op);\n"
            "  }\n"
            "  return 0;\n"
            "}\n"
        ))
        assert "CWE-484" not in _cats(tmp_path)


# ── CWE-396 / CWE-755 split (item 59) ─────────────────────────────────
class TestGenericCatchSplit:
    def test_python_except_exception_is_396(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def run(fn):\n"
            "    try:\n"
            "        fn()\n"
            "    except Exception as exc:\n"
            "        report(exc)\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-396" in cats
        assert "CWE-755" not in cats

    def test_python_tuple_generic_is_396(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def run(fn):\n"
            "    try:\n"
            "        fn()\n"
            "    except (ValueError, Exception):\n"
            "        report()\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-396" in cats
        assert "CWE-755" not in cats

    def test_bare_except_stays_755(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def run(fn):\n"
            "    try:\n"
            "        fn()\n"
            "    except:\n"
            "        report()\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-755" in cats
        assert "CWE-396" not in cats

    def test_java_catch_exception_is_396(self, tmp_path):
        _write(tmp_path, "Svc.java", (
            "class Svc {\n"
            "  void run() {\n"
            "    try { act(); } catch (Exception e) { log(e); }\n"
            "  }\n"
            "}\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-396" in cats
        assert "CWE-755" not in cats

    def test_exception_in_initializer_error_clean(self, tmp_path):
        """The `\\b` after the type name must block `ExceptionInInitializerError`."""
        _write(tmp_path, "Svc.java", (
            "class Svc {\n"
            "  void run() {\n"
            "    try { act(); } catch (ExceptionInInitializerError e) { log(e); }\n"
            "  }\n"
            "}\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-396" not in cats
        assert "CWE-755" not in cats

    def test_specific_type_clean(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def run(fn):\n"
            "    try:\n"
            "        fn()\n"
            "    except ValueError as exc:\n"
            "        report(exc)\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-396" not in cats
        assert "CWE-755" not in cats

    def test_optional_catch_binding_is_755_in_csharp(self, tmp_path):
        _write(tmp_path, "Svc.cs", (
            "class Svc {\n"
            "  void Run() {\n"
            "    try { Act(); } catch { Report(); }\n"
            "  }\n"
            "}\n"
        ))
        cats = _cats(tmp_path)
        assert "CWE-755" in cats
        assert "CWE-396" not in cats

    def test_optional_catch_binding_not_reported_in_typescript(self, tmp_path):
        """`} catch {` is the idiomatic TS spelling for discarding the error
        object: measured 986 occurrences in ONE TypeScript codebase and 1,390
        rows across five repositories. At that volume the row is a style
        census, so the JS/TS half of the arm is deliberately not shipped."""
        _write(tmp_path, "svc.ts", (
            "export function run(fn: () => void) {\n"
            "  try { fn(); } catch { report(); }\n"
            "}\n"
        ))
        assert _cats(tmp_path) == []

    def test_cxx_catch_all_is_755_in_cpp(self, tmp_path):
        _write(tmp_path, "svc.cpp", (
            "void run() {\n"
            "  try { act(); } catch (...) { report(); }\n"
            "}\n"
        ))
        assert "CWE-755" in _cats(tmp_path)

    def test_cxx_catch_all_prose_in_docstring_clean(self, tmp_path):
        """`catch(...)` is C++ syntax; ungated it matched Python prose."""
        _write(tmp_path, "helper.py", (
            "def collect(lines, lineno):\n"
            "    \"\"\"Collect the body following an except: or\n"
            "    catch(...) header.\n"
            "    \"\"\"\n"
            "    return lines[lineno:]\n"
        ))
        assert "CWE-755" not in _cats(tmp_path)

    def test_xor_invariant_one_row_per_line(self, tmp_path):
        """396 XOR 755 — never two broad-catch rows for one handler."""
        _write(tmp_path, "svc.py", (
            "def run(fn):\n"
            "    try:\n"
            "        fn()\n"
            "    except Exception:\n"
            "        report()\n"
        ))
        cats = _cats(tmp_path)
        assert cats.count("CWE-396") + cats.count("CWE-755") == 1


# ── CWE-394: unexpected status code (item 60) ─────────────────────────
# CWE-394 (response body used without a status check) was REVERTED after
# measurement: both rows on a real tree were false, firing on ordinary control
# flow (`if (options.replacement?.length === 2)`) rather than a consumed
# response body. The arm matcher does not establish that the value is a
# response at all.



class TestJ2eeExit:
    def test_servlet_exit_fires(self, tmp_path):
        _write(tmp_path, "Admin.java", (
            "import javax.servlet.http.HttpServlet;\n"
            "public class Admin extends HttpServlet {\n"
            "  protected void doGet() {\n"
            "    System.exit(0);\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-382" in _cats(tmp_path)

    def test_ejb_runtime_halt_fires(self, tmp_path):
        _write(tmp_path, "Worker.java", (
            "import jakarta.ejb.Stateless;\n"
            "@Stateless\n"
            "public class Worker {\n"
            "  public void run() {\n"
            "    Runtime.getRuntime().halt(1);\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-382" in _cats(tmp_path)

    def test_main_entrypoint_clean(self, tmp_path):
        _write(tmp_path, "Tool.java", (
            "import javax.servlet.ServletException;\n"
            "public class Tool {\n"
            "  public static void main(String[] a) {\n"
            "    System.exit(0);\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-382" not in _cats(tmp_path)

    def test_spring_rest_controller_clean(self, tmp_path):
        """A Spring service owns its JVM — `@RestController` is not a
        container-managed J2EE component."""
        _write(tmp_path, "Admin.java", (
            "@RestController\n"
            "public class Admin {\n"
            "  public void shutdown() {\n"
            "    System.exit(0);\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-382" not in _cats(tmp_path)

    def test_one_row_per_file(self, tmp_path):
        _write(tmp_path, "Admin.java", (
            "import javax.servlet.http.HttpServlet;\n"
            "public class Admin extends HttpServlet {\n"
            "  protected void doGet() {\n"
            "    System.exit(0);\n"
            "    System.exit(1);\n"
            "  }\n"
            "}\n"
        ))
        assert _cats(tmp_path).count("CWE-382") == 1


# ── CWE-397: generic throws / raise (item 58) ─────────────────────────
class TestGenericThrows:
    def test_cpp_dynamic_exception_spec_fires(self, tmp_path):
        _write(tmp_path, "svc.cpp", (
            "#include <exception>\n"
            "void work() throw(std::exception) {\n"
            "  act();\n"
            "}\n"
        ))
        cats = _cats(tmp_path, check_uncaught_exception)
        assert "CWE-397" in cats

    def test_cpp_specific_spec_clean(self, tmp_path):
        _write(tmp_path, "svc.cpp", (
            "#include <exception>\n"
            "void work() throw(MyError) {\n"
            "  act();\n"
            "}\n"
        ))
        assert "CWE-397" not in _cats(tmp_path, check_uncaught_exception)

    def test_csharp_generic_throw_fires(self, tmp_path):
        _write(tmp_path, "Svc.cs", (
            "class Svc {\n"
            "  void Work() {\n"
            "    throw new Exception(\"boom\");\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-397" in _cats(tmp_path, check_uncaught_exception)

    def test_csharp_specific_throw_clean(self, tmp_path):
        _write(tmp_path, "Svc.cs", (
            "class Svc {\n"
            "  void Work() {\n"
            "    throw new InvalidOperationException(\"boom\");\n"
            "  }\n"
            "}\n"
        ))
        assert "CWE-397" not in _cats(tmp_path, check_uncaught_exception)

    def test_python_raise_exception_fires(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def work(x):\n"
            "    if not x:\n"
            "        raise Exception('bad input')\n"
            "    return x\n"
        ))
        assert "CWE-397" in _cats(tmp_path, check_uncaught_exception)

    def test_python_specific_raise_clean(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def work(x):\n"
            "    if not x:\n"
            "        raise ValueError('bad input')\n"
            "    return x\n"
        ))
        assert "CWE-397" not in _cats(tmp_path, check_uncaught_exception)

    def test_python_one_row_per_file(self, tmp_path):
        _write(tmp_path, "svc.py", (
            "def work(x):\n"
            "    if not x:\n"
            "        raise Exception('a')\n"
            "    if x < 0:\n"
            "        raise Exception('b')\n"
            "    return x\n"
        ))
        assert _cats(tmp_path, check_uncaught_exception).count("CWE-397") == 1

    def test_javadoc_throws_no_longer_fires_248(self, tmp_path):
        """`* @throws Exception` is documentation, not a declaration."""
        _write(tmp_path, "Svc.java", (
            "class Svc {\n"
            "  /**\n"
            "   * @throws Exception if it fails\n"
            "   */\n"
            "  void work() {\n"
            "    act();\n"
            "  }\n"
            "}\n"
        ))
        assert _cats(tmp_path, check_uncaught_exception) == []

    def test_throws_inside_string_literal_clean(self, tmp_path):
        _write(tmp_path, "Svc.java", (
            "class Svc {\n"
            "  String doc() {\n"
            "    return \"throws Exception\";\n"
            "  }\n"
            "}\n"
        ))
        assert _cats(tmp_path, check_uncaught_exception) == []

    def test_java_declaration_still_reported(self, tmp_path):
        """The anchored signature keeps the Java declaration reachable."""
        _write(tmp_path, "Svc.java", (
            "class Svc {\n"
            "  public void work() throws Exception {\n"
            "    act();\n"
            "  }\n"
            "}\n"
        ))
        assert _cats(tmp_path, check_uncaught_exception) != []


# ── prose guard (rule 6 / P7) ─────────────────────────────────────────
class TestProseGuard:
    def test_markdown_prose_is_not_scanned(self, tmp_path):
        _write(tmp_path, "HANDLING.md", (
            "# Error handling policy\n"
            "\n"
            "Never write a handler like this:\n"
            "\n"
            "    except Exception:\n"
            "        pass\n"
            "\n"
            "Always name the exception type.\n"
        ))
        assert _cats(tmp_path) == []
