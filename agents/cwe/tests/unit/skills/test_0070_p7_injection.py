"""Feature 0070 P7 — A05 injection specialisations in ``injection_check``.

Six reviewed items, each shipped with its clean twin:

* **CWE-564** Hibernate HQL/JPQL built by concatenation. CWE-89 keeps
  ownership of any line its own patterns already match (skill findings are
  not cross-deduplicated), and the generic-DAO idiom
  (``createQuery("from " + entityClass.getSimpleName() + ...)``) is
  type-derived, not injectable.
* **CWE-80** template escape hatches (``|safe``, ``mark_safe(``,
  ``template.HTML(``, ``raw``/``html_safe``, Blade ``{!! !!}``). Every
  non-literal-argument lookahead must reject the empty-argument form —
  ``mark_safe()`` inside a remediation string is prose, not a sink.
* **CWE-88** argument injection through argv-list spawns. Shell-literal
  argv[0] stays with CWE-78, and the taint gate is the *qualified* request
  accessor set — a bare word ``request`` contributed zero recall and all of
  the FP surface.
* **CWE-470** unsafe reflection, anchored on class/module *selectors* only.
  ``.newInstance()`` / ``.getMethod()`` are the invocation, not the
  selection, and ``__import__(var)`` is already reported by
  ``obfuscation.computed_import``.
* **CWE-98** PHP file inclusion, direct and one-hop. A superglobal used only
  as a map *key* (``include $map[$tpl];``) is the declared-safe shape.
* **CWE-83** script in an attribute. The nested-quote spelling
  ``onclick="f('${x}')"`` is the dominant true positive and must be
  matchable; a loop counter in the interpolation is the dominant false one.

Prose files (``.md``/``.rst``/``.txt``/...) are excluded skill-wide: measured
5 rows on a real tree, all documentation that merely *names* a sink.
"""

from pathlib import Path

import pytest

from cwe_agent.skills.injection_check import check_injection

_MODULE_SRC = (
    Path(__file__).resolve().parents[3] / "cwe_agent" / "skills" / "injection_check.py"
).read_text()


def _cats(tmp_path, cat: str) -> list[dict]:
    return [
        f
        for f in check_injection(str(tmp_path))["findings"]
        if f["category"] == cat
    ]


def _write(tmp_path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body)


# === Attestation ==========================================================


@pytest.mark.parametrize("cwe", ["564", "80", "88", "470", "98", "83"])
def test_category_literal_is_present_in_source(cwe):
    """The coverage extractor only sees a literal category. An f-string built
    category would detect and still be reported unreachable."""
    assert (
        f'"category": "CWE-{cwe}"' in _MODULE_SRC
        or f'category="CWE-{cwe}"' in _MODULE_SRC
    )


# === Item 28: CWE-564 Hibernate ===========================================

HQL_CONCAT = """package app;
public class UserDao {
    public Object find(String name) {
        return em.createQuery("from User where name='" + name + "'").getSingleResult();
    }
}
"""
HQL_SPRING_QUERY = """package app;
public interface UserRepo {
    @Query("SELECT u FROM User u WHERE u.email = '" + email + "'")
    User byEmail(String email);
}
"""
HQL_NATIVE = """package app;
public class Dao {
    public Object f(String a) {
        return em.createNativeQuery("SELECT * FROM t WHERE a=" + a).getResultList();
    }
}
"""
HQL_PARAMETERISED = """package app;
public class UserDao {
    public Object find(String name) {
        return em.createQuery("from User where name = :name")
            .setParameter("name", name).getSingleResult();
    }
}
"""
HQL_TYPE_DERIVED = """package app;
public class GenericDao<T> {
    public Object all() {
        return em.createQuery("from " + entityClass.getSimpleName() + " where id=:id");
    }
}
"""
HQL_CONSTANT_OPERAND = """package app;
public class Dao {
    static final String BASE_HQL = "from User";
    public Object all() {
        return em.createQuery(BASE_HQL + ORDER_CLAUSE).getResultList();
    }
}
"""
HQL_FORMAT_IS_CWE89 = """package app;
public class Dao {
    public Object f(String y) {
        return em.createQuery(String.format("SELECT x FROM y WHERE z=%s", y));
    }
}
"""


class TestHibernateInjection:
    @pytest.mark.parametrize(
        "body", [HQL_CONCAT, HQL_SPRING_QUERY, HQL_NATIVE]
    )
    def test_concatenated_query_flagged(self, tmp_path, body):
        _write(tmp_path, "Dao.java", body)
        assert len(_cats(tmp_path, "CWE-564")) == 1

    @pytest.mark.parametrize(
        "body",
        [HQL_PARAMETERISED, HQL_TYPE_DERIVED, HQL_CONSTANT_OPERAND],
    )
    def test_clean_twins_not_flagged(self, tmp_path, body):
        _write(tmp_path, "Dao.java", body)
        assert _cats(tmp_path, "CWE-564") == []

    def test_cwe89_keeps_ownership_of_its_own_line(self, tmp_path):
        """One row per line: the ``String.format`` shape is already a CWE-89
        pattern, so 564 must yield rather than stack."""
        _write(tmp_path, "Dao.java", HQL_FORMAT_IS_CWE89)
        rows = check_injection(str(tmp_path))["findings"]
        on_line = [r for r in rows if r["line_start"] == 4]
        assert [r["category"] for r in on_line] == ["CWE-89"]

    def test_not_applied_to_python(self, tmp_path):
        _write(
            tmp_path,
            "dao.py",
            'q = session.createQuery("from User where n=\'" + name + "\'")\n',
        )
        assert _cats(tmp_path, "CWE-564") == []


# === Item 29: CWE-80 template escape hatches ==============================


class TestTemplateEscapeHatches:
    def test_jinja_safe_filter_flagged(self, tmp_path):
        _write(tmp_path, "profile.html", "<div>{{ user_bio|safe }}</div>\n")
        assert len(_cats(tmp_path, "CWE-80")) == 1

    def test_mark_safe_flagged(self, tmp_path):
        _write(tmp_path, "views.py", "def v(r):\n    return mark_safe(user_input)\n")
        assert len(_cats(tmp_path, "CWE-80")) == 1

    def test_go_template_html_flagged(self, tmp_path):
        _write(tmp_path, "render.go", "func r() { out = template.HTML(userBio) }\n")
        assert len(_cats(tmp_path, "CWE-80")) == 1

    def test_erb_raw_flagged(self, tmp_path):
        _write(tmp_path, "show.erb", "<p><%= raw @comment.body %></p>\n")
        assert len(_cats(tmp_path, "CWE-80")) == 1

    def test_blade_double_bang_flagged(self, tmp_path):
        _write(tmp_path, "show.blade.php", "<div>{!! $userBio !!}</div>\n")
        assert len(_cats(tmp_path, "CWE-80")) == 1

    def test_empty_argument_is_not_a_sink(self, tmp_path):
        """The ``)``-hole: a remediation string naming the API is prose."""
        _write(
            tmp_path,
            "recommend.py",
            'MSG = "Remove |safe filter or mark_safe() call"\n',
        )
        assert _cats(tmp_path, "CWE-80") == []

    def test_autoescaped_interpolation_not_flagged(self, tmp_path):
        _write(tmp_path, "profile.html", "<div>{{ user_bio }}</div>\n")
        assert _cats(tmp_path, "CWE-80") == []

    def test_i18n_pipe_form_not_flagged(self, tmp_path):
        _write(
            tmp_path, "banner.html", "<p>{{ 'welcome.body'|translate|safe }}</p>\n"
        )
        assert _cats(tmp_path, "CWE-80") == []

    def test_i18n_call_form_not_flagged(self, tmp_path):
        """The declared FP shape is Rails ``t('k').html_safe`` — no pipe."""
        _write(tmp_path, "show.erb", "<p><%= t('welcome.body').html_safe %></p>\n")
        assert _cats(tmp_path, "CWE-80") == []

    def test_prose_file_is_not_scanned(self, tmp_path):
        _write(tmp_path, "SECURITY.md", "Never use mark_safe(user_input) here.\n")
        assert _cats(tmp_path, "CWE-80") == []


# === Item 30: CWE-88 argument injection ===================================

PY_ARGV = """import subprocess
def run(req):
    target = req.query["host"]
    subprocess.run(["curl", "--url=" + target])
"""
NODE_ARGV = """const { execFile } = require('child_process')
function log (req, res) {
  execFile("git", ["log", "--pretty=" + req.query.fmt], cb)
}
"""
GO_ARGV = """package main

func h(w http.ResponseWriter, r *http.Request) {
    exec.Command("tar", "-C"+r.FormValue("dir"), "-xf", "a.tar")
}
"""
PY_ARGV_STATIC = """import subprocess
def run(path):
    subprocess.run(["ls", "-la", path])
"""
PY_ARGV_SHELL0 = """import subprocess
def run(req):
    subprocess.run(["sh", "-c", "echo " + req.query.x])
"""
PY_ARGV_SEPARATOR = """import subprocess
def run(req):
    subprocess.run(["git", "log", "--", "--pretty=" + req.query.fmt])
"""
JAVA_PROCESSBUILDER = """package app;
public class R {
    void run(HttpServletRequest request) {
        new ProcessBuilder("tar", "-C" + request.getParameter("d")).start();
    }
}
"""


class TestArgumentInjection:
    @pytest.mark.parametrize(
        ("name", "body"),
        [("run.py", PY_ARGV), ("log.js", NODE_ARGV), ("h.go", GO_ARGV)],
    )
    def test_built_option_flag_with_taint_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert len(_cats(tmp_path, "CWE-88")) == 1

    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("run.py", PY_ARGV_STATIC),
            ("run.py", PY_ARGV_SHELL0),
            ("run.py", PY_ARGV_SEPARATOR),
        ],
    )
    def test_clean_twins_not_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert _cats(tmp_path, "CWE-88") == []

    def test_processbuilder_stays_cwe78_only(self, tmp_path):
        """Verbatim duplicate sink: CWE-78 owns ``new ProcessBuilder(``."""
        _write(tmp_path, "R.java", JAVA_PROCESSBUILDER)
        rows = check_injection(str(tmp_path))["findings"]
        on_line = [r for r in rows if r["line_start"] == 4]
        assert [r["category"] for r in on_line] == ["CWE-78"]

    def test_commander_dot_command_is_not_a_java_sink(self, tmp_path):
        _write(
            tmp_path,
            "cli.ts",
            'program.command("deploy " + req.query.env).action(run)\n',
        )
        assert _cats(tmp_path, "CWE-88") == []


# === Item 31: CWE-470 unsafe reflection ===================================

JAVA_FORNAME = """package app;
public class R {
    public Object load(HttpServletRequest request) throws Exception {
        String cls = request.getParameter("cls");
        return Class.forName(cls);
    }
}
"""
PY_IMPORT_MODULE = """import importlib
def load(request):
    name = request.GET["mod"]
    return importlib.import_module(name)
"""
JS_REQUIRE = """function load (req) {
  return require(req.query.plugin)
}
"""
JS_REQUIRE_LITERAL = """const _ = require('lodash')
"""
JS_REQUIRE_UNTAINTED = """function pick (candidate) {
  return require(candidate)
}
"""
PY_DUNDER_IMPORT = """def load(request):
    modname = request.GET["m"]
    return __import__(modname)
"""
JAVA_NEWINSTANCE_ONLY = """package app;
public class R {
    public Object make(HttpServletRequest request, Class<?> clazz) throws Exception {
        String t = request.getParameter("t");
        return clazz.newInstance();
    }
}
"""
JAVA_ALLOWLISTED = """package app;
public class R {
    public Object load(HttpServletRequest request) throws Exception {
        String cls = ALLOWED_CLASSES.get(request.getParameter("t"));
        return Class.forName(cls);
    }
}
"""


class TestUnsafeReflection:
    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("R.java", JAVA_FORNAME),
            ("load.py", PY_IMPORT_MODULE),
            ("load.js", JS_REQUIRE),
        ],
    )
    def test_tainted_selector_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert len(_cats(tmp_path, "CWE-470")) == 1

    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("a.js", JS_REQUIRE_LITERAL),
            ("b.js", JS_REQUIRE_UNTAINTED),
            ("R.java", JAVA_ALLOWLISTED),
        ],
    )
    def test_clean_twins_not_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert _cats(tmp_path, "CWE-470") == []

    def test_dunder_import_left_to_obfuscation_check(self, tmp_path):
        _write(tmp_path, "load.py", PY_DUNDER_IMPORT)
        assert _cats(tmp_path, "CWE-470") == []

    def test_newinstance_is_not_an_anchor(self, tmp_path):
        _write(tmp_path, "R.java", JAVA_NEWINSTANCE_ONLY)
        assert _cats(tmp_path, "CWE-470") == []


# === Item 32: CWE-98 PHP file inclusion ===================================

PHP_DIRECT = """<?php
include($_GET['page']);
"""
PHP_CONCAT = """<?php
require_once("modules/" . $_REQUEST['m'] . ".php");
"""
PHP_ONE_HOP = """<?php
$tpl = $_GET['tpl'];
include $tpl;
"""
PHP_MAP_KEY = """<?php
$pages = ['home' => 'home.php'];
include $pages[$_GET['p']];
"""
PHP_ONE_HOP_MAP = """<?php
$map = ['a' => 'a.php'];
$tpl = $_GET['tpl'];
include $map[$tpl];
"""
PHP_BASENAME = """<?php
include basename($_GET['page']);
"""
PHP_HOP_SANITISED = """<?php
$template = basename($_GET['template']);
include "templates/" . $template;
"""


class TestPhpFileInclusion:
    @pytest.mark.parametrize(
        "body", [PHP_DIRECT, PHP_CONCAT, PHP_ONE_HOP]
    )
    def test_untrusted_include_flagged(self, tmp_path, body):
        _write(tmp_path, "index.php", body)
        assert len(_cats(tmp_path, "CWE-98")) == 1

    @pytest.mark.parametrize(
        "body", [PHP_MAP_KEY, PHP_ONE_HOP_MAP, PHP_BASENAME]
    )
    def test_clean_twins_not_flagged(self, tmp_path, body):
        _write(tmp_path, "index.php", body)
        assert _cats(tmp_path, "CWE-98") == []

    def test_sanitised_at_the_hop_not_flagged(self, tmp_path):
        """The guard is applied at the ASSIGNMENT, not on the include line."""
        _write(tmp_path, "index.php", PHP_HOP_SANITISED)
        assert _cats(tmp_path, "CWE-98") == []

    def test_extension_gated_to_php(self, tmp_path):
        _write(tmp_path, "loader.py", "include($_GET['page'])\n")
        assert _cats(tmp_path, "CWE-98") == []


# === Item 33: CWE-83 script in attributes =================================

ATTR_NESTED_QUOTES = (
    "<button onclick=\"doThing('${req.query.name}')\">go</button>\n"
)
ATTR_JINJA = "<a href=\"#\" onclick=\"select('{{ user_email }}')\">x</a>\n"
ATTR_SET_ATTRIBUTE = "el.setAttribute('onclick', handlerFromRequest)\n"
ATTR_JS_SCHEME = "link.href = \"javascript:show('\" + userName + \"')\"\n"
ATTR_LOOP_COUNTER = "<button onclick=\"selectRow({{ loop.index }})\">x</button>\n"
ATTR_LITERAL_SET = "el.setAttribute('onclick', 'toggle()')\n"
ATTR_STATIC = "<button onclick=\"doThing()\">go</button>\n"
ATTR_INTERPOLATION_ONLY = "<div>{{ user_email }}</div>\n"


class TestScriptInAttribute:
    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("page.html", ATTR_NESTED_QUOTES),
            ("page.html", ATTR_JINJA),
            ("dom.js", ATTR_SET_ATTRIBUTE),
            ("dom.js", ATTR_JS_SCHEME),
        ],
    )
    def test_dynamic_handler_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert len(_cats(tmp_path, "CWE-83")) == 1

    @pytest.mark.parametrize(
        ("name", "body"),
        [
            ("page.html", ATTR_LOOP_COUNTER),
            ("dom.js", ATTR_LITERAL_SET),
            ("page.html", ATTR_STATIC),
            ("page.html", ATTR_INTERPOLATION_ONLY),
        ],
    )
    def test_clean_twins_not_flagged(self, tmp_path, name, body):
        _write(tmp_path, name, body)
        assert _cats(tmp_path, "CWE-83") == []


# === Skill-wide prose guard ===============================================


class TestProseGuard:
    def test_markdown_sink_mention_is_not_a_finding(self, tmp_path):
        _write(
            tmp_path,
            "SKILLS.md",
            "Detects `element.innerHTML = userInput` and `eval(userCode)`.\n",
        )
        assert check_injection(str(tmp_path))["findings"] == []

    def test_source_file_sink_still_found(self, tmp_path):
        _write(tmp_path, "dom.js", "element.innerHTML = userInput\n")
        assert len(_cats(tmp_path, "CWE-79")) == 1
