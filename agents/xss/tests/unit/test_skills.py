"""Unit tests for all 5 XSS scanner skills."""

import pytest

from xss_agent.config import AGENT_INFO, ALL_CATEGORIES, CONFIG_SCHEMA
from xss_agent.skills import SKILL_MAP, SKILL_TOOLS
from xss_agent.skills.reflected_xss_check import (
    TEMPLATE_UNSAFE_PATTERNS,
    DOM_WRITE_PATTERNS,
    SERVER_RESPONSE_PATTERNS,
    check_reflected_xss,
)
from xss_agent.skills.stored_xss_check import (
    DB_READ_INDICATORS,
    UNSAFE_RENDER_PATTERNS,
    MARKDOWN_RAW_PATTERNS,
    check_stored_xss,
)
from xss_agent.skills.dom_xss_check import (
    SOURCE_PATTERNS,
    SINK_PATTERNS,
    SOURCE_TO_SINK_PATTERNS,
    check_dom_xss,
)
from xss_agent.skills.template_injection_check import (
    JINJA2_PATTERNS,
    HANDLEBARS_PATTERNS,
    EJS_PATTERNS,
    GO_TEMPLATE_PATTERNS,
    check_template_injection,
)
from xss_agent.skills.header_injection_check import (
    HEADER_INJECTION_PATTERNS,
    WEAK_CSP_PATTERNS,
    META_REFRESH_PATTERNS,
    check_header_injection,
)


# =============================================================================
# Config tests
# =============================================================================

class TestXSSConfig:
    """Tests for XSS agent configuration."""

    def test_all_categories_complete(self):
        assert len(ALL_CATEGORIES) == 5
        assert "reflected_xss" in ALL_CATEGORIES
        assert "stored_xss" in ALL_CATEGORIES
        assert "dom_xss" in ALL_CATEGORIES
        assert "template_injection" in ALL_CATEGORIES
        assert "header_injection" in ALL_CATEGORIES

    def test_agent_type_is_xss(self):
        assert AGENT_INFO["type"] == "xss"

    def test_agent_name(self):
        assert AGENT_INFO["name"] == "XSS Scanner"

    def test_config_schema_enum_matches_categories(self):
        schema_enum = CONFIG_SCHEMA["properties"]["categories"]["items"]["enum"]
        assert schema_enum == ALL_CATEGORIES

    def test_skills_list_matches_categories(self):
        assert len(AGENT_INFO["skills"]) == 5

    def test_skill_map_keys_match_categories(self):
        assert set(SKILL_MAP.keys()) == set(ALL_CATEGORIES)

    def test_skill_tools_count(self):
        assert len(SKILL_TOOLS) == 5


# =============================================================================
# Reflected XSS pattern tests
# =============================================================================

class TestReflectedXSSPatterns:
    """Tests for reflected XSS regex patterns."""

    def test_detects_safe_filter(self):
        line = '{{ user_input | safe }}'
        assert any(p.search(line) for p in TEMPLATE_UNSAFE_PATTERNS)

    def test_detects_mark_safe(self):
        line = 'return mark_safe(user_input)'
        assert any(p.search(line) for p in TEMPLATE_UNSAFE_PATTERNS)

    def test_detects_blade_unescaped(self):
        line = '{!! $user_input !!}'
        assert any(p.search(line) for p in TEMPLATE_UNSAFE_PATTERNS)

    def test_detects_dangerously_set_inner_html(self):
        line = '<div dangerouslySetInnerHTML={{__html: data}} />'
        assert any(p.search(line) for p in TEMPLATE_UNSAFE_PATTERNS)

    def test_detects_innerhtml_with_variable(self):
        line = 'element.innerHTML = userInput;'
        assert any(p.search(line) for p in DOM_WRITE_PATTERNS)

    def test_detects_document_write_concat(self):
        line = 'document.write("<p>" + input + "</p>")'
        assert any(p.search(line) for p in DOM_WRITE_PATTERNS)

    def test_detects_express_res_send(self):
        line = 'res.send(req.query.name)'
        assert any(p.search(line) for p in SERVER_RESPONSE_PATTERNS)

    def test_detects_php_echo_get(self):
        line = 'echo $_GET["name"];'
        assert any(p.search(line) for p in SERVER_RESPONSE_PATTERNS)

    def test_detects_go_fprintf_request(self):
        line = 'fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("q"))'
        assert any(p.search(line) for p in SERVER_RESPONSE_PATTERNS)

    def test_no_false_positive_static_innerhtml(self):
        line = 'element.innerHTML = "<p>static</p>";'
        assert not any(p.search(line) for p in DOM_WRITE_PATTERNS)

    def test_no_false_positive_textcontent(self):
        line = 'element.textContent = userInput;'
        assert not any(p.search(line) for p in DOM_WRITE_PATTERNS)


class TestCheckReflectedXSS:
    """Tests for the reflected XSS skill function."""

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_reflected_xss(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_empty_dir_no_findings(self, source_dir):
        result = check_reflected_xss(str(source_dir))
        assert result["findings"] == []

    def test_detects_safe_filter(self, source_dir):
        code = 'def view(request):\n    return render(user_input | safe)\n'
        (source_dir / "views.py").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-79"
        assert result["findings"][0]["severity"] == "critical"

    def test_detects_innerhtml_variable(self, source_dir):
        code = 'function render(data) {\n  el.innerHTML = data;\n}\n'
        (source_dir / "app.js").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "innerHTML" in result["findings"][0]["title"]

    def test_detects_express_response(self, source_dir):
        code = 'app.get("/q", (req, res) => {\n  res.send(req.query.search);\n});\n'
        (source_dir / "server.js").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-79"

    def test_safe_code_no_findings(self, source_dir):
        code = 'element.textContent = userInput;\n'
        (source_dir / "safe.js").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert result["findings"] == []

    def test_sanitized_context_no_findings(self, source_dir):
        code = (
            'const clean = DOMPurify.sanitize(input);\n'
            'el.innerHTML = clean;\n'
        )
        (source_dir / "safe.js").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert result["findings"] == []

    def test_comment_ignored(self, source_dir):
        code = '// el.innerHTML = userInput;\n'
        (source_dir / "app.js").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert result["findings"] == []

    def test_finding_has_required_fields(self, source_dir):
        code = 'def view():\n    return mark_safe(data)\n'
        (source_dir / "views.py").write_text(code)
        result = check_reflected_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        required = {
            "severity", "category", "title", "description",
            "file_path", "line_start", "line_end", "recommendation",
        }
        assert required.issubset(finding.keys())


# =============================================================================
# Stored XSS pattern tests
# =============================================================================

class TestStoredXSSPatterns:
    """Tests for stored XSS regex patterns."""

    def test_db_read_indicator_query(self):
        line = 'result = db.query("SELECT * FROM posts")'
        assert DB_READ_INDICATORS.search(line)

    def test_db_read_indicator_objects(self):
        line = 'posts = Post.objects.all()'
        assert DB_READ_INDICATORS.search(line)

    def test_unsafe_render_safe_filter(self):
        line = '{{ post.content | safe }}'
        assert any(p.search(line) for p in UNSAFE_RENDER_PATTERNS)

    def test_unsafe_render_v_html(self):
        line = '<div v-html="post.content"></div>'
        assert any(p.search(line) for p in UNSAFE_RENDER_PATTERNS)

    def test_markdown_raw_pattern(self):
        line = 'html = markdown.markdown(post.body) | safe'
        assert any(p.search(line) for p in MARKDOWN_RAW_PATTERNS)


class TestCheckStoredXSS:
    """Tests for the stored XSS skill function."""

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_stored_xss(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result

    def test_empty_dir_no_findings(self, source_dir):
        result = check_stored_xss(str(source_dir))
        assert result["findings"] == []

    def test_detects_db_to_safe_filter(self, source_dir):
        code = (
            'def view(request):\n'
            '    posts = Post.objects.all()\n'
            '    for p in posts:\n'
            '        html = p.content | safe\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-79"
        assert "Stored" in result["findings"][0]["title"]

    def test_detects_db_to_innerhtml(self, source_dir):
        code = (
            'async function load() {\n'
            '  const data = await db.query("SELECT body FROM posts");\n'
            '  for (const row of data) {\n'
            '    el.innerHTML = row.body;\n'
            '  }\n'
            '}\n'
        )
        (source_dir / "app.js").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_finding_without_db_read(self, source_dir):
        code = 'el.innerHTML = someVar;\n'
        (source_dir / "app.js").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert result["findings"] == []

    def test_detects_markdown_as_raw_html(self, source_dir):
        code = (
            'def render_post(post):\n'
            '    html_content = Markup(markdown.markdown(post.body))\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "markdown" in result["findings"][0]["title"].lower()

    def test_detects_upload_as_html(self, source_dir):
        code = (
            'def serve_file(request):\n'
            '    return send_file(upload_path, content_type="text/html")\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "upload" in result["findings"][0]["title"].lower()

    def test_sanitized_no_findings(self, source_dir):
        code = (
            'def view():\n'
            '    posts = Post.objects.all()\n'
            '    clean = bleach.clean(posts[0].body)\n'
            '    el.innerHTML = clean\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_stored_xss(str(source_dir))
        assert result["findings"] == []


# =============================================================================
# DOM XSS pattern tests
# =============================================================================

class TestDOMXSSPatterns:
    """Tests for DOM XSS regex patterns."""

    def test_source_location_hash(self):
        line = 'var input = location.hash;'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_location_search(self):
        line = 'var q = location.search;'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_document_url(self):
        line = 'var url = document.URL;'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_document_referrer(self):
        line = 'var ref = document.referrer;'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_window_name(self):
        line = 'var name = window.name;'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_postmessage(self):
        line = 'window.addEventListener("message", handler);'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_source_urlsearchparams(self):
        line = 'const params = new URLSearchParams(location.search);'
        assert any(p.search(line) for p in SOURCE_PATTERNS)

    def test_sink_innerhtml(self):
        line = 'el.innerHTML = data;'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_document_write(self):
        line = 'document.write(content);'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_eval(self):
        line = 'eval(code);'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_jquery_html(self):
        line = '$("#el").html(data);'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_insert_adjacent(self):
        line = 'el.insertAdjacentHTML("beforeend", data);'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_v_html(self):
        line = '<div v-html="data"></div>'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_sink_angular_innerhtml(self):
        line = '<div [innerHTML]="data"></div>'
        assert any(p.search(line) for p in SINK_PATTERNS)

    def test_direct_flow_innerhtml_location(self):
        line = 'el.innerHTML = location.hash;'
        assert any(p.search(line) for p in SOURCE_TO_SINK_PATTERNS)

    def test_direct_flow_document_write_location(self):
        line = 'document.write(location.search);'
        assert any(p.search(line) for p in SOURCE_TO_SINK_PATTERNS)


class TestCheckDOMXSS:
    """Tests for the DOM XSS skill function."""

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_dom_xss(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result

    def test_empty_dir_no_findings(self, source_dir):
        result = check_dom_xss(str(source_dir))
        assert result["findings"] == []

    def test_detects_direct_source_to_sink(self, source_dir):
        code = (
            'function render() {\n'
            '  el.innerHTML = location.hash;\n'
            '}\n'
        )
        (source_dir / "app.js").write_text(code)
        result = check_dom_xss(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-79"
        assert result["findings"][0]["severity"] == "critical"

    def test_detects_source_near_sink(self, source_dir):
        code = (
            'function handleMessage() {\n'
            '  const params = new URLSearchParams(location.search);\n'
            '  const q = params.get("q");\n'
            '  document.write(q);\n'
            '}\n'
        )
        (source_dir / "app.js").write_text(code)
        result = check_dom_xss(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_safe_textcontent_no_findings(self, source_dir):
        code = (
            'function render() {\n'
            '  const q = location.hash;\n'
            '  el.textContent = q;\n'
            '}\n'
        )
        (source_dir / "app.js").write_text(code)
        result = check_dom_xss(str(source_dir))
        assert result["findings"] == []

    def test_only_scans_js_ts_files(self, source_dir):
        code = 'el.innerHTML = location.hash;\n'
        (source_dir / "app.py").write_text(code)
        result = check_dom_xss(str(source_dir))
        assert result["findings"] == []

    def test_sanitized_no_findings(self, source_dir):
        code = (
            'function render() {\n'
            '  const raw = location.hash;\n'
            '  const clean = DOMPurify.sanitize(raw);\n'
            '  el.innerHTML = clean;\n'
            '}\n'
        )
        (source_dir / "app.js").write_text(code)
        result = check_dom_xss(str(source_dir))
        assert result["findings"] == []


# =============================================================================
# Template Injection pattern tests
# =============================================================================

class TestTemplateInjectionPatterns:
    """Tests for template injection regex patterns."""

    def test_jinja2_template_user_input(self):
        line = 'tmpl = Template(request.form["tmpl"])'
        assert any(p.search(line) for p in JINJA2_PATTERNS)

    def test_jinja2_from_string_user_input(self):
        line = 'tmpl = env.from_string(request.args.get("t"))'
        assert any(p.search(line) for p in JINJA2_PATTERNS)

    def test_handlebars_triple_stache(self):
        line = '<p>{{{user_content}}}</p>'
        assert any(p.search(line) for p in HANDLEBARS_PATTERNS)

    def test_ejs_render_user_input(self):
        line = 'html = ejs.render(req.body.template, data)'
        assert any(p.search(line) for p in EJS_PATTERNS)

    def test_go_template_html_request(self):
        line = 'safe := template.HTML(r.FormValue("content"))'
        assert any(p.search(line) for p in GO_TEMPLATE_PATTERNS)


class TestCheckTemplateInjection:
    """Tests for the template injection skill function."""

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_template_injection(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result

    def test_empty_dir_no_findings(self, source_dir):
        result = check_template_injection(str(source_dir))
        assert result["findings"] == []

    def test_detects_jinja2_ssti(self, source_dir):
        code = (
            'def render(request):\n'
            '    tmpl = Template(request.form["template"])\n'
            '    return tmpl.render()\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_template_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-1336"
        assert result["findings"][0]["severity"] == "critical"

    def test_detects_handlebars_triple_stache(self, source_dir):
        code = '<div>{{{userContent}}}</div>\n'
        (source_dir / "template.js").write_text(code)
        result = check_template_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "Handlebars" in result["findings"][0]["title"]

    def test_detects_ejs_render_user_input(self, source_dir):
        code = (
            'app.post("/preview", (req, res) => {\n'
            '  const html = ejs.render(req.body.template, {});\n'
            '  res.send(html);\n'
            '});\n'
        )
        (source_dir / "server.js").write_text(code)
        result = check_template_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "EJS" in result["findings"][0]["title"]

    def test_detects_go_template_html(self, source_dir):
        code = (
            'func handler(w http.ResponseWriter, r *http.Request) {\n'
            '    safe := template.HTML(r.FormValue("content"))\n'
            '}\n'
        )
        (source_dir / "handler.go").write_text(code)
        result = check_template_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "Go" in result["findings"][0]["title"]

    def test_safe_render_template_no_findings(self, source_dir):
        code = (
            'def view(request):\n'
            '    return render_template("index.html", data=data)\n'
        )
        (source_dir / "views.py").write_text(code)
        result = check_template_injection(str(source_dir))
        assert result["findings"] == []

    def test_safe_static_template_no_findings(self, source_dir):
        code = 'tmpl = Template("Hello, {{ name }}")\n'
        (source_dir / "views.py").write_text(code)
        result = check_template_injection(str(source_dir))
        assert result["findings"] == []

    def test_comment_ignored(self, source_dir):
        code = '# Template(request.form["tmpl"])\n'
        (source_dir / "views.py").write_text(code)
        result = check_template_injection(str(source_dir))
        assert result["findings"] == []


# =============================================================================
# Header Injection pattern tests
# =============================================================================

class TestHeaderInjectionPatterns:
    """Tests for header injection regex patterns."""

    def test_header_set_with_user_input(self):
        line = 'w.Header().Set("Location", r.FormValue("next"))'
        assert any(p.search(line) for p in HEADER_INJECTION_PATTERNS)

    def test_content_disposition_user_input(self):
        line = 'Content-Disposition: attachment; filename=' + 'req.query.name'
        assert any(p.search(line) for p in HEADER_INJECTION_PATTERNS)

    def test_weak_csp_unsafe_inline(self):
        line = "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'"
        assert any(p.search(line) for p in WEAK_CSP_PATTERNS)

    def test_weak_csp_unsafe_eval(self):
        line = "Content-Security-Policy: script-src 'unsafe-eval'"
        assert any(p.search(line) for p in WEAK_CSP_PATTERNS)

    def test_weak_csp_wildcard(self):
        line = "Content-Security-Policy: default-src *"
        assert any(p.search(line) for p in WEAK_CSP_PATTERNS)

    def test_meta_refresh_user_url(self):
        line = '<meta http-equiv="refresh" content="0;url=' + '{{ request.args.get("next") }}'
        assert any(p.search(line) for p in META_REFRESH_PATTERNS)


class TestCheckHeaderInjection:
    """Tests for the header injection skill function."""

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_header_injection(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result

    def test_empty_dir_no_findings(self, source_dir):
        result = check_header_injection(str(source_dir))
        assert result["findings"] == []

    def test_detects_header_injection(self, source_dir):
        code = (
            'func handler(w http.ResponseWriter, r *http.Request) {\n'
            '    w.Header().Set("Location", r.FormValue("next"))\n'
            '}\n'
        )
        (source_dir / "handler.go").write_text(code)
        result = check_header_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-113"

    def test_detects_weak_csp(self, source_dir):
        code = (
            'app.use((req, res, next) => {\n'
            "    res.setHeader('Content-Security-Policy', \"script-src 'unsafe-inline'\");\n"
            '    next();\n'
            '});\n'
        )
        (source_dir / "middleware.js").write_text(code)
        result = check_header_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-644"

    def test_detects_meta_refresh(self, source_dir):
        code = '<meta http-equiv="refresh" content="0;url={{ request.args.get(\'next\') }}">\n'
        (source_dir / "template.py").write_text(code)
        result = check_header_injection(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_safe_sanitized_no_findings(self, source_dir):
        code = (
            'func handler(w http.ResponseWriter, r *http.Request) {\n'
            '    next := sanitize(r.FormValue("next"))\n'
            '    w.Header().Set("Location", next)\n'
            '}\n'
        )
        (source_dir / "handler.go").write_text(code)
        result = check_header_injection(str(source_dir))
        assert result["findings"] == []

    def test_safe_nonce_csp_no_findings(self, source_dir):
        code = (
            "app.use((req, res, next) => {\n"
            "    res.setHeader('Content-Security-Policy', "
            "\"script-src 'nonce-abc123' 'strict-dynamic' 'unsafe-inline'\");\n"
            "    next();\n"
            "});\n"
        )
        (source_dir / "middleware.js").write_text(code)
        result = check_header_injection(str(source_dir))
        assert result["findings"] == []

    def test_comment_ignored(self, source_dir):
        code = "// Content-Security-Policy: script-src 'unsafe-inline'\n"
        (source_dir / "config.js").write_text(code)
        result = check_header_injection(str(source_dir))
        assert result["findings"] == []


# =============================================================================
# Finding format validation
# =============================================================================

class TestFindingFormat:
    """Tests verifying finding dict structure across all skills."""

    REQUIRED_FIELDS = {
        "severity", "category", "title", "description",
        "file_path", "line_start", "line_end", "recommendation",
    }

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

    @pytest.fixture()
    def source_dir(self, tmp_path):
        return tmp_path

    def _write_and_check(self, source_dir, filename, code, check_fn):
        (source_dir / filename).write_text(code)
        result = check_fn(str(source_dir))
        assert len(result["findings"]) >= 1, f"Expected findings from {check_fn.__name__}"
        finding = result["findings"][0]
        assert self.REQUIRED_FIELDS.issubset(finding.keys())
        assert finding["severity"] in self.VALID_SEVERITIES
        assert isinstance(finding["line_start"], int)
        assert isinstance(finding["line_end"], int)
        assert finding["line_start"] > 0

    def test_reflected_xss_finding_format(self, source_dir):
        code = 'def view():\n    return mark_safe(data)\n'
        self._write_and_check(source_dir, "views.py", code, check_reflected_xss)

    def test_stored_xss_finding_format(self, source_dir):
        code = (
            'def view():\n'
            '    result = db.query("SELECT * FROM t")\n'
            '    html = result | safe\n'
        )
        self._write_and_check(source_dir, "views.py", code, check_stored_xss)

    def test_dom_xss_finding_format(self, source_dir):
        code = 'function r() {\n  el.innerHTML = location.hash;\n}\n'
        self._write_and_check(source_dir, "app.js", code, check_dom_xss)

    def test_template_injection_finding_format(self, source_dir):
        code = 'def view():\n    t = Template(request.form["t"])\n'
        self._write_and_check(source_dir, "views.py", code, check_template_injection)

    def test_header_injection_finding_format(self, source_dir):
        code = 'func h(w http.ResponseWriter, r *http.Request) {\n    w.Header().Set("Location", r.FormValue("u"))\n}\n'
        self._write_and_check(source_dir, "handler.go", code, check_header_injection)
