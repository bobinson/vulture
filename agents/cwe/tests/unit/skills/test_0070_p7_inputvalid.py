"""Feature 0070 P7 — input-validation detection backlog (group `inputvalid`).

Five reviewed items, all owned by ``input_validation_check.py``:

* **CWE-776** Recursive entity references (XML entity expansion). Every
  alternative pins the *unsafe literal*, so the hardening twin cannot match.
  CWE-611 keeps the line when a bitmask names an entity/DTD flag.
* **CWE-103** Struts ``ValidatorForm`` subclass whose ``validate()`` override
  never calls ``super.validate()``.
* **CWE-183** Permissive allow-list: an identifier-shaped allow-list name that
  opens a collection literal containing an executable/active member, in a file
  with a real server-side upload API.
* **CWE-646** Reliance on the uploaded file's name/extension for an accept
  decision, server-side accessors only, with the content-sniffing suppressor
  anchored to an import.
* **CWE-36** Absolute path traversal via a *substitution sanitiser*
  (``replace('..','')``). Membership / prefix checks are deliberately NOT
  detected: they cannot be told apart from the correct canonicalise-then-contain
  defence without dataflow.

Each rule carries at least one positive and one minimally-different clean twin.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.input_validation_check import check_input_validation


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_input_validation(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# --------------------------------------------------------------------------
# CWE-776 — recursive entity expansion (XEE / billion laughs)
# --------------------------------------------------------------------------

_XEE_POSITIVES = {
    "lxml_huge_tree": ("x.py", "parser = etree.XMLParser(huge_tree=True)\n"),
    "expand_entity_refs": (
        "X.java", "factory.setExpandEntityReferences(true);\n"
    ),
    "secure_processing_off": (
        "Y.java",
        "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);\n",
    ),
    "secure_processing_property_off": (
        "Z.java",
        'f.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", false);\n',
    ),
    "support_dtd_on": (
        "W.java",
        "f.setProperty(XMLInputFactory.SUPPORT_DTD, true);\n",
    ),
    "forbid_entities_off": (
        "d.py", "tree = parse(payload, forbid_entities=False)\n"
    ),
    "expansion_limit_zero": (
        "V.java", "tf.setAttribute(ENTITY_EXPANSION_LIMIT, 0);\n"
    ),
    "expansion_limit_quoted_zero": (
        "U.java",
        'tf.setAttribute("http://apache.org/xml/features/entityExpansionLimit", "0");\n',
    ),
    "parse_huge_flag": (
        "p.ts", "const option = libxml2.ParseOption.XML_PARSE_HUGE\n"
    ),
    "huge_tree_option_object": (
        "q.js", "const doc = parseDoc(data, { huge_tree: true })\n"
    ),
}

_XEE_CLEAN_TWINS = {
    "lxml_huge_tree": ("x.py", "parser = etree.XMLParser(huge_tree=False)\n"),
    "expand_entity_refs": (
        "X.java", "factory.setExpandEntityReferences(false);\n"
    ),
    "secure_processing_off": (
        "Y.java",
        "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n",
    ),
    "secure_processing_property_off": (
        "Z.java",
        'f.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);\n',
    ),
    "support_dtd_on": (
        "W.java",
        "f.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n",
    ),
    "forbid_entities_off": (
        "d.py", "tree = parse(payload, forbid_entities=True)\n"
    ),
    "expansion_limit_zero": (
        "V.java", "tf.setAttribute(ENTITY_EXPANSION_LIMIT, 2000);\n"
    ),
    "expansion_limit_quoted_zero": (
        "U.java",
        'tf.setAttribute("http://apache.org/xml/features/entityExpansionLimit", "2000");\n',
    ),
    "parse_huge_flag": (
        "p.ts", "const option = libxml2.ParseOption.XML_PARSE_NOBLANKS\n"
    ),
    "huge_tree_option_object": (
        "q.js", "const doc = parseDoc(data, { huge_tree: false })\n"
    ),
}


class TestCWE776EntityExpansion:
    def test_every_unsafe_literal_fires(self):
        for label, (name, body) in _XEE_POSITIVES.items():
            assert _of(_run({name: body}), "CWE-776"), f"{label} must fire"

    def test_every_hardening_twin_is_clean(self):
        for label, (name, body) in _XEE_CLEAN_TWINS.items():
            assert not _of(_run({name: body}), "CWE-776"), (
                f"{label} hardening twin must not fire"
            )

    def test_constant_definition_is_not_a_configuration(self):
        """A binding that *defines* the flag value is not a parser setting."""
        body = (
            "export const ParseOption = {\n"
            "  XML_PARSE_HUGE: 1 << 19,\n"
            "}\n"
        )
        assert not _of(_run({"opts.ts": body}), "CWE-776")

    def test_prose_mention_is_not_a_finding(self):
        """A hardening guide that names the option is not an instance of it."""
        body = (
            "# XML hardening\n\n"
            "Never call etree.XMLParser(huge_tree=True) on untrusted input.\n"
        )
        assert not _of(_run({"SECURITY.md": body}), "CWE-776")

    def test_bitmask_with_entity_flag_yields_exactly_one_row(self):
        """P5 row-stacking: CWE-611 owns the line, CWE-776 stands down."""
        body = (
            "const option = libxml2.ParseOption.XML_PARSE_HUGE | "
            "libxml2.ParseOption.XML_PARSE_NOENT\n"
        )
        findings = _run({"x.ts": body})
        on_line = [f for f in findings if f["line_start"] == 1]
        assert len(on_line) == 1, on_line
        assert on_line[0]["category"] == "CWE-611"


# --------------------------------------------------------------------------
# CWE-103 — Struts incomplete validate()
# --------------------------------------------------------------------------

_STRUTS_VULN = (
    "public class ProfileForm extends ValidatorForm {\n"
    "  private String email;\n"
    "  public ActionErrors validate(ActionMapping mapping, HttpServletRequest req) {\n"
    "    ActionErrors errors = new ActionErrors();\n"
    "    return errors;\n"
    "  }\n"
    "}\n"
)


class TestCWE103StrutsValidate:
    def test_override_without_super_call_fires(self):
        hits = _of(_run({"ProfileForm.java": _STRUTS_VULN}), "CWE-103")
        assert len(hits) == 1
        assert hits[0]["line_start"] == 3

    def test_action_form_variant_fires(self):
        body = _STRUTS_VULN.replace("ValidatorForm", "ValidatorActionForm")
        assert _of(_run({"P.java": body}), "CWE-103")

    def test_super_validate_call_is_clean(self):
        body = _STRUTS_VULN.replace(
            "    ActionErrors errors = new ActionErrors();",
            "    ActionErrors errors = super.validate(mapping, req);",
        )
        assert not _of(_run({"ProfileForm.java": body}), "CWE-103")

    def test_abstract_base_class_is_clean(self):
        body = _STRUTS_VULN.replace(
            "public class ProfileForm", "public abstract class BaseForm"
        )
        assert not _of(_run({"BaseForm.java": body}), "CWE-103")

    def test_plain_action_form_is_clean(self):
        body = _STRUTS_VULN.replace("ValidatorForm", "ActionForm")
        assert not _of(_run({"ProfileForm.java": body}), "CWE-103")

    def test_one_row_per_file(self):
        body = _STRUTS_VULN + _STRUTS_VULN
        assert len(_of(_run({"P.java": body}), "CWE-103")) == 1


# --------------------------------------------------------------------------
# CWE-183 — permissive list of allowed inputs
# --------------------------------------------------------------------------

_UPLOAD_PRELUDE = "const store = multer({ dest: '/var/tmp' })\n"
_ALLOWLIST_VULN = (
    _UPLOAD_PRELUDE + "const allowedExtensions = ['.png', '.jpg', '.svg']\n"
)


class TestCWE183PermissiveAllowlist:
    def test_active_member_in_allowlist_fires(self):
        hits = _of(_run({"up.js": _ALLOWLIST_VULN}), "CWE-183")
        assert len(hits) == 1
        assert hits[0]["line_start"] == 2

    def test_mime_allowlist_fires(self):
        body = (
            _UPLOAD_PRELUDE
            + "const allowedMimeTypes = ['image/png', 'image/svg+xml']\n"
        )
        assert _of(_run({"up.js": body}), "CWE-183")

    def test_inert_member_list_is_clean(self):
        body = _ALLOWLIST_VULN.replace("'.svg'", "'.gif'")
        assert not _of(_run({"up.js": body}), "CWE-183")

    def test_no_upload_api_in_file_is_clean(self):
        body = "const allowedExtensions = ['.png', '.svg']\n"
        assert not _of(_run({"cfg.js": body}), "CWE-183")

    def test_prose_table_is_clean(self):
        """`[_\\s]*` in the name turned the rule into a prose matcher."""
        body = (
            "Upload guide\n\n"
            "Accepted formats: png, jpg, svg (multer handles the request).\n"
        )
        assert not _of(_run({"UPLOADS.md": body}), "CWE-183")

    def test_boolean_flag_is_clean(self):
        """`allowExtension: true` is a feature switch, not an allow-list."""
        body = _UPLOAD_PRELUDE + "const opts = { allowExtension: true, svg: '.svg' }\n"
        assert not _of(_run({"up.js": body}), "CWE-183")

    def test_deny_list_naming_is_clean(self):
        body = _UPLOAD_PRELUDE + "const deniedAllowedTypes = ['.svg', '.html']\n"
        assert not _of(_run({"up.js": body}), "CWE-183")

    def test_syntax_highlight_list_is_clean(self):
        body = _UPLOAD_PRELUDE + "const allowedLanguages = ['html', 'php']\n"
        assert not _of(_run({"up.js": body}), "CWE-183")


# --------------------------------------------------------------------------
# CWE-646 — reliance on file name / extension
# --------------------------------------------------------------------------

_RELIANCE_VULN = (
    _UPLOAD_PRELUDE
    + "function accept (file) {\n"
    + "  const ext = file.originalname.split('.').pop()\n"
    + "  if (ext !== 'png') { return reject('bad type') }\n"
    + "}\n"
)


class TestCWE646FilenameReliance:
    def test_extension_split_then_reject_fires(self):
        hits = _of(_run({"h.js": _RELIANCE_VULN}), "CWE-646")
        assert len(hits) == 1
        assert hits[0]["line_start"] == 3

    def test_python_splitext_fires(self):
        body = (
            "def save(req):\n"
            "    doc = req.files['doc']\n"
            "    ext = os.path.splitext(request.files['doc'].filename)[1]\n"
            "    if ext not in ALLOWED:\n"
            "        raise ValueError(ext)\n"
        )
        assert _of(_run({"h.py": body}), "CWE-646")

    def test_content_sniffing_import_suppresses(self):
        body = "const FileType = require('file-type')\n" + _RELIANCE_VULN
        assert not _of(_run({"h.js": body}), "CWE-646")

    def test_ordinary_filetype_identifier_does_not_suppress(self):
        """The bare substring `file-?type` matched `fileType` and disabled the
        rule exactly where it should fire."""
        body = _RELIANCE_VULN + "const fileType = file.mimetype\n"
        assert _of(_run({"h.js": body}), "CWE-646")

    def test_browser_file_api_is_clean(self):
        body = _RELIANCE_VULN.replace("file.originalname", "file.name")
        assert not _of(_run({"h.js": body}), "CWE-646")

    def test_label_without_decision_is_clean(self):
        body = (
            _UPLOAD_PRELUDE
            + "function label (file) {\n"
            + "  const ext = file.originalname.split('.').pop()\n"
            + "  card.badge = ext\n"
            + "}\n"
        )
        assert not _of(_run({"h.js": body}), "CWE-646")

    def test_no_upload_api_in_file_is_clean(self):
        body = _RELIANCE_VULN.replace(_UPLOAD_PRELUDE, "")
        assert not _of(_run({"h.js": body}), "CWE-646")

    def test_random_rename_is_clean(self):
        body = _RELIANCE_VULN.replace(
            "  const ext = file.originalname.split('.').pop()",
            "  const ext = randomUUID() + file.originalname.split('.').pop()",
        )
        assert not _of(_run({"h.js": body}), "CWE-646")


# --------------------------------------------------------------------------
# CWE-36 — absolute path traversal (substitution sanitiser only)
# --------------------------------------------------------------------------


class TestCWE36AbsolutePathTraversal:
    def test_js_replace_sanitiser_fires(self):
        body = (
            "function read (userPath) {\n"
            "  const cleaned = userPath.replace('../', '')\n"
            "  fs.readFile(cleaned, cb)\n"
            "}\n"
        )
        hits = _of(_run({"r.js": body}), "CWE-36")
        assert len(hits) == 1
        assert hits[0]["line_start"] == 2

    def test_python_re_sub_sanitiser_fires(self):
        """Nested form: the shared SCANNER_DEF_LINE guard (`=\\s*re\\.`) skips the
        `cleaned = re.sub(...)` assignment shape, so only this one is reachable."""
        body = (
            "def read(name):\n"
            "    return open(re.sub(r'\\.\\./', '', name)).read()\n"
        )
        assert _of(_run({"r.py": body}), "CWE-36")

    def test_python_replace_sanitiser_fires(self):
        body = (
            "def read(name):\n"
            "    cleaned = name.replace('../', '')\n"
            "    return open(cleaned).read()\n"
        )
        assert _of(_run({"r.py": body}), "CWE-36")

    def test_go_replaceall_sanitiser_fires(self):
        body = (
            "func read(name string) {\n"
            '\tcleaned := strings.ReplaceAll(name, "..", "")\n'
            "\tos.Open(cleaned)\n"
            "}\n"
        )
        assert _of(_run({"r.go": body}), "CWE-36")

    def test_php_str_replace_sanitiser_fires(self):
        body = (
            "<?php\n"
            "$clean = str_replace('..', '', $_GET['f']);\n"
            "$data = file_get_contents($clean);\n"
        )
        assert _of(_run({"r.php": body}), "CWE-36")

    def test_ruby_gsub_sanitiser_fires(self):
        body = (
            "def read(name)\n"
            "  clean = name.gsub('..', '')\n"
            "  File.open(clean).read\n"
            "end\n"
        )
        assert _of(_run({"r.rb": body}), "CWE-36")

    def test_canonicaliser_nearby_suppresses(self):
        """`path.relative` containment already handles an absolute input."""
        body = (
            "function read (userPath) {\n"
            "  const rel = path.relative(root, userPath)\n"
            "  const cleaned = rel.replace('../', '')\n"
            "  fs.readFile(cleaned, cb)\n"
            "}\n"
        )
        assert not _of(_run({"r.js": body}), "CWE-36")

    def test_repeat_until_stable_strip_is_clean(self):
        body = (
            "function read (userPath) {\n"
            "  while (userPath.includes('../')) {\n"
            "    userPath = userPath.replace('../', '')\n"
            "  }\n"
            "  fs.readFile(userPath, cb)\n"
            "}\n"
        )
        assert not _of(_run({"r.js": body}), "CWE-36")

    def test_no_filesystem_sink_is_clean(self):
        body = (
            "function label (userPath) {\n"
            "  return userPath.replace('../', '')\n"
            "}\n"
        )
        assert not _of(_run({"r.js": body}), "CWE-36")

    def test_membership_check_is_not_detected(self):
        """Prefix / membership arms were deleted: 4/4 measured rows were false
        and they cannot be separated from the correct relative-containment
        defence without dataflow."""
        body = (
            "function read (userPath) {\n"
            "  if (userPath.startsWith('..')) { throw new Error('bad') }\n"
            "  fs.readFile(userPath, cb)\n"
            "}\n"
        )
        assert not _of(_run({"r.js": body}), "CWE-36")

    def test_child_suppresses_parent_on_the_same_line(self):
        """P5 row-stacking: exactly one row when CWE-22 also matches."""
        body = (
            "def read(user_file, base):\n"
            "    return open(os.path.join(base, user_file.replace('..', '')))\n"
        )
        findings = _run({"r.py": body})
        on_line = [f for f in findings if f["line_start"] == 2]
        assert len(on_line) == 1, on_line
        assert on_line[0]["category"] == "CWE-36"


# --------------------------------------------------------------------------
# Attestation — the literals must be visible to the coverage extractor
# --------------------------------------------------------------------------


class TestAttestationLiterals:
    def test_new_categories_are_source_literals(self):
        from cwe_agent.skills import input_validation_check as mod

        text = Path(mod.__file__).read_text(encoding="utf-8")
        for cwe in ("36", "103", "183", "646", "776"):
            assert f'category="CWE-{cwe}"' in text or f'"category": "CWE-{cwe}"' in text

    def test_findings_are_catalog_enriched(self):
        hits = _of(_run({"ProfileForm.java": _STRUTS_VULN}), "CWE-103")
        assert hits and hits[0].get("cwe_name")
