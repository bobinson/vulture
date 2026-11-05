"""E2E: the catalog's signature tier reports every file it fires in, and two of
its signatures judge the construct they report.

Business contract
-----------------
* A deterministic signature (``cwe.sig.*``) is reported in every file it fires
  in. It was capped at 8 files per CWE in walk order, so files walked earlier
  (juice-shop's ``data/static/codefixes/`` snippets, which sort before
  ``routes/``) pushed two real NoSQL injections out of the report, and adding
  an unrelated file could make a reported row disappear. The keyword rows and
  the Class/Pillar rollups keep their per-CWE cap.
* ``cwe.sig.xpath``: compiling a regular expression (``re.compile``,
  ``regex.compile``, Java ``Pattern.compile``) is not building an XPath
  expression, whatever the pattern holds.
* ``cwe.sig.loginj``: the log call must log a request value, either directly
  or through a variable assigned from one on the lines above it. A request word
  elsewhere in the window, or in the message text, is not a source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

NOSQL_WHERE = (
    'app.get("/orders", (req, res) => {\n'
    "  const id = req.query.id;\n"
    '  Order.find({ $where: "this.id == " + id }).then((rows) => res.json(rows));\n'
    "});\n"
)


def _scan(root: Path, files: dict[str, str]) -> list[dict]:
    from cwe_agent.skills.catalog_detector import check_catalog_generic
    from shared.tools.file_scanner import clear_caches

    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    clear_caches()
    return check_catalog_generic(str(root))["findings"]


def _where(rows: list[dict], root: Path, check: str) -> set[str]:
    return {Path(f["file_path"]).relative_to(root).as_posix() for f in rows if f["check_id"] == check}


@pytest.fixture
def root(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("tree")


def test_every_file_a_signature_fires_in_is_reported(root: Path) -> None:
    files = {f"routes/orders{i:02d}.js": NOSQL_WHERE for i in range(12)}
    assert _where(_scan(root, files), root, "cwe.sig.nosql_where") == set(files)


def test_files_walked_earlier_do_not_push_a_later_one_out(root: Path) -> None:
    files = {f"challenges/snippet{i:02d}.js": NOSQL_WHERE for i in range(10)}
    files["routes/trackOrder.js"] = NOSQL_WHERE
    assert "routes/trackOrder.js" in _where(_scan(root, files), root, "cwe.sig.nosql_where")


XPATH_NOT = {
    "re_compile.py": (
        "def parse(request):\n"
        "    sep = request.args.get('sep')\n"
        '    header = re.compile(r"^--- (?P<rel>.+?)(?: \\(lines [^)]*\\))? ---$" + sep)\n'
    ),
    "regex_compile.py": (
        "def parse(request):\n"
        "    word = request.args.get('w')\n"
        '    found = regex.compile(r"\\b" + word + r"{1,3}")\n'
    ),
    "Pattern.java": (
        "class P {\n"
        "  Pattern p(HttpServletRequest request) {\n"
        '    return Pattern.compile("^" + request.getParameter("p") + "$");\n'
        "  }\n"
        "}\n"
    ),
}
XPATH_YES = {
    "Lookup.java": (
        "class Lookup {\n"
        "  Object find(XPath xpath, HttpServletRequest request) throws Exception {\n"
        '    String name = request.getParameter("name");\n'
        "    return xpath.compile(\"//user[@name='\" + name + \"']\");\n"
        "  }\n"
        "}\n"
    ),
    "find.js": (
        "app.get('/a', (req, res) => {\n"
        "  const hit = document.evaluate(\"//a[@id='\" + req.query.id + \"']\", doc);\n"
        "});\n"
    ),
}


@pytest.mark.parametrize("rel", sorted(XPATH_NOT))
def test_a_regex_compile_is_not_an_xpath_sink(root: Path, rel: str) -> None:
    assert not _where(_scan(root, {rel: XPATH_NOT[rel]}), root, "cwe.sig.xpath")


@pytest.mark.parametrize("rel", sorted(XPATH_YES))
def test_an_xpath_built_from_request_input_is_reported(root: Path, rel: str) -> None:
    assert _where(_scan(root, {rel: XPATH_YES[rel]}), root, "cwe.sig.xpath") == {rel}


LOGINJ_NOT = {
    "hangup.ts": (
        "export function onHangup(event: Event, input: Input) {\n"
        "  const cause = event.payload.hangup_cause;\n"
        "  console.warn(`[telnyx] Unknown hangup cause: ${cause}`);\n"
        "}\n"
    ),
    "report.py": (
        "def report(logger, request):\n"
        "    count = len(load_users())\n"
        '    logger.info("user count: " + str(count))\n'
    ),
    "Audit.java": (
        "class Audit {\n"
        "  void run(HttpServletRequest request) {\n"
        "    int jobs = queue.size();\n"
        '    logger.info("request queue depth " + jobs);\n'
        "  }\n"
        "}\n"
    ),
}
LOGINJ_YES = {
    "search.js": (
        "app.get('/search', (req, res) => {\n"
        "  console.log(`search q=${req.query.q}`);\n"
        "});\n"
    ),
    "login.py": (
        "def handle(logger, request):\n"
        '    name = request.args.get("name")\n'
        '    logger.info("login by " + name)\n'
    ),
    "upload.py": (
        "def upload(logger, request):\n"
        '    filename = request.files["f"].filename\n'
        '    logger.error(f"upload rejected for {filename}")\n'
    ),
    "Search.java": (
        "class Search {\n"
        "  void run(HttpServletRequest request) {\n"
        '    logger.warn("term=" + request.getParameter("q"));\n'
        "  }\n"
        "}\n"
    ),
}


@pytest.mark.parametrize("rel", sorted(LOGINJ_NOT))
def test_a_log_line_without_a_request_value_is_not_log_injection(root: Path, rel: str) -> None:
    assert not _where(_scan(root, {rel: LOGINJ_NOT[rel]}), root, "cwe.sig.loginj")


@pytest.mark.parametrize("rel", sorted(LOGINJ_YES))
def test_a_logged_request_value_is_log_injection(root: Path, rel: str) -> None:
    assert _where(_scan(root, {rel: LOGINJ_YES[rel]}), root, "cwe.sig.loginj") == {rel}
