"""XSS agent false positives measured on a real target (3 of 3 rows false).

1. CWE-113: `Location.*(?:...|user|...)` was unanchored at BOTH ends, so
       const hasProfileLocation = Boolean(userAddressData);
   matched -- "Location" inside `hasProfileLocation`, "user" inside
   `userAddressData`. A header name must appear AS a header (quoted, or
   followed by a colon), and the taint token must be a whole word.

2. CWE-79: `dangerouslySetInnerHTML={{ __html: extractStyle(cache) }}` is the
   canonical Next.js / antd SSR style-extraction idiom. The content is
   framework-generated CSS on a <style> element, not reflected user input --
   and "Reflected XSS" is doubly wrong, since no request-echo path exists.
"""


from shared.tools.framework_html import (
    is_framework_style_injection as _is_framework_style_injection,
)
from xss_agent.skills.header_injection_check import HEADER_INJECTION_PATTERNS


def _matches(line: str) -> bool:
    return any(p.search(line) for p in HEADER_INJECTION_PATTERNS)


class TestHeaderInjectionAnchoring:
    def test_identifier_containing_location_is_not_a_header(self):
        assert not _matches("    const hasProfileLocation = Boolean(userAddressData);")

    def test_identifier_containing_content_type_is_not_a_header(self):
        assert not _matches("    const contentTypeLabel = userLabel;")

    def test_real_location_header_still_matches(self):
        assert _matches('  res.setHeader("Location", req.query.next);')

    def test_real_content_disposition_still_matches(self):
        assert _matches('  res.setHeader("Content-Disposition", `attachment; filename=${req.query.f}`);')

    def test_colon_form_header_still_matches(self):
        assert _matches('  raw += `Location: ${req.query.redirect}\\r\\n`;')


class TestFrameworkStyleInjection:
    def test_antd_extract_style(self):
        assert _is_framework_style_injection(
            '      <style id="antd" dangerouslySetInnerHTML={{ __html: extractStyle(cache, true) }} />')

    def test_next_initial_props_styles(self):
        assert _is_framework_style_injection(
            '        <style dangerouslySetInnerHTML={{ __html: style }} />')

    def test_real_user_html_is_not_excused(self):
        assert not _is_framework_style_injection(
            '  <div dangerouslySetInnerHTML={{ __html: req.query.bio }} />')

    def test_div_with_styled_content_is_not_excused(self):
        assert not _is_framework_style_injection(
            '  <div dangerouslySetInnerHTML={{ __html: userProvidedStyle }} />')


class TestSiblingSkillAlsoSuppresses:
    """stored_xss_check matches `dangerouslySetInnerHTML` too.

    Fixing reflected_xss_check alone left the SAME line reported by its sibling
    — verified live on `_document.tsx:86` after the first fix shipped. Third
    instance of one lesson in this feature: an FP fix must be applied to every
    skill and every agent that can reach the line, not just the one that was
    measured.
    """

    def test_stored_xss_skips_framework_styles(self, tmp_path):
        import json

        from xss_agent.skills.stored_xss_check import check_stored_xss

        src = tmp_path / "a.tsx"
        src.write_text(
            "const rows = await db.query('select * from t');\n"
            "export default function Doc({ style }) {\n"
            "  return <style dangerouslySetInnerHTML={{ __html: style }} />;\n"
            "}\n"
        )
        fn = getattr(check_stored_xss, "func", check_stored_xss)
        out = fn(str(tmp_path))
        out = out if isinstance(out, dict) else json.loads(out)
        assert [f for f in out.get("findings", []) if f.get("category") == "CWE-79"] == []
