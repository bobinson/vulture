"""CWE-79 must not fire on framework SSR style extraction either.

DRY completion. The same idiom was suppressed in the xss agent
(reflected_xss_check) and the asvs agent (V3.2.2), but CWE — the PRIMARY
detector — still flagged it, so the false positive was never removed from the
product: cross-agent dedup had simply been awarding those lines to the xss
agent's specialist row. With xss silenced, CWE's row wins dedup and the same
two `critical`/`high` rows reappear under a different label.

Measured on togetherapp before this fix: CWE emitted CWE-79 for
`frontend/app/AntdRegistry.tsx:22` and `frontend/pages/_document.tsx:86`, the
exact two lines the other two agents had already been taught to ignore.

All three agents now consume ONE predicate, shared/tools/framework_html.
"""

import json
import os
import tempfile

from cwe_agent.skills.injection_check import check_injection

ANTD_MULTILINE = """\
export default function StyledJsxRegistry() {
  return (
    <style
      id="antd"
      dangerouslySetInnerHTML={{ __html: extractStyle(cache, true) }}
    />
  );
}
"""

NEXT_SINGLE_LINE = """\
export default function Doc({ style }) {
  return <style dangerouslySetInnerHTML={{ __html: style }} />;
}
"""

REAL_XSS = """\
export default function Bio({ req }) {
  return <div dangerouslySetInnerHTML={{ __html: req.query.bio }} />;
}
"""


def _xss_rows(src: str, ext: str = ".tsx") -> list[dict]:
    d = tempfile.mkdtemp()
    with open(os.path.join(d, f"a{ext}"), "w") as fh:
        fh.write(src)
    out = check_injection(d)
    out = out if isinstance(out, dict) else json.loads(out)
    return [f for f in out.get("findings", []) if f.get("category") == "CWE-79"]


class TestFrameworkStylesNotFlagged:
    def test_antd_multiline_jsx(self):
        assert _xss_rows(ANTD_MULTILINE) == []

    def test_next_single_line(self):
        assert _xss_rows(NEXT_SINGLE_LINE) == []


class TestRealXssStillFlagged:
    def test_user_html_in_a_div_still_reports(self):
        assert len(_xss_rows(REAL_XSS)) >= 1
