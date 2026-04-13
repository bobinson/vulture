"""XSS vulnerability scanner agent definition."""

from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from xss_agent.config import ALL_CATEGORIES
from xss_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are an XSS (Cross-Site Scripting) Security Auditor.
Analyze source code for XSS vulnerabilities across 5 categories:
- Reflected XSS (CWE-79): User input reflected in HTTP responses without encoding.
  Look for template unsafe rendering (|safe, mark_safe, {!! !!}, <%- %>),
  direct DOM writes (innerHTML, document.write) with variables,
  React dangerouslySetInnerHTML, server response writes with request params.
- Stored XSS (CWE-79): Database/store reads rendered unsafely in templates.
  Look for DB results in |safe/innerHTML, ORM fields in unsafe contexts,
  markdown rendered as raw HTML, user uploads served as text/html.
- DOM-based XSS (CWE-79): JavaScript source-to-sink data flows.
  Sources: location.hash/search/href, document.URL/referrer, window.name,
  postMessage, URLSearchParams.
  Sinks: innerHTML, outerHTML, document.write, eval, setTimeout/setInterval
  with strings, new Function, $.html(), insertAdjacentHTML, v-html, [innerHTML].
- Template Injection (CWE-1336): Server-side template injection leading to XSS.
  Look for Jinja2 Template(user_input), Django Template(user_input).render(),
  Handlebars triple-stache {{{var}}}, EJS ejs.render(user_input),
  Go template.HTML(user_input).
- Header Injection (CWE-113/CWE-644): HTTP headers that enable XSS.
  Look for user input in Content-Type/Content-Disposition/Link headers,
  missing/weak CSP (unsafe-inline, unsafe-eval), missing X-Content-Type-Options.
Report findings with severity, CWE ID, affected file, line numbers, and
actionable recommendations including specific sanitization functions.
Use prior findings from memory to avoid redundant analysis."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the XSS vulnerability audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(
        source_path, "xss", preloaded=preloaded, max_findings=max_f,
    )

    use_llm_val = config.get("use_llm")
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="XSS categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
    )
