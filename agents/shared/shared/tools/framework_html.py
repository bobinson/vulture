"""Framework-generated HTML/CSS injection that is not an XSS sink.

Server-side rendering frameworks inject their own extracted CSS through the
same API an XSS would use::

    <style id="antd" dangerouslySetInnerHTML={{ __html: extractStyle(cache) }} />
    <style dangerouslySetInnerHTML={{ __html: style }} />      (Next initialProps)

The injected content is framework-GENERATED CSS on a ``<style>`` element, not
reflected request data. Measured on one real target: this idiom accounted for
2 of the 3 findings the XSS agent produced (both ``critical``, both labelled
"Reflected XSS" -- doubly wrong, since no request-echo path exists) and 2 of
the ASVS agent's V3.2.2 rows. Two agents, one cause, so the predicate lives
here rather than being written twice.

Both halves are required: a ``<style>`` element AND a recognised CSS-producing
expression. A ``<div>`` carrying ``__html`` is never excused, whatever it holds
-- that is what keeps this from becoming a blanket ``dangerouslySetInnerHTML``
amnesty.
"""
from __future__ import annotations

import re

_STYLE_ELEMENT = re.compile(r"<style\b", re.IGNORECASE)

_CSS_SOURCE = re.compile(
    r"__html\s*:\s*(?:"
    r"extractStyle\s*\("                     # antd / @ant-design/cssinjs
    r"|\w{0,40}[Ss]tyles?\b"                 # style, styles, initialProps.styles
    r"|\w{0,30}\.styles\b"
    r"|getStyleElement\s*\("                 # styled-components SSR
    r"|sheet\.getStyleTags\s*\("
    r")"
)

# JSX routinely splits one element across lines, so the element and the
# attribute are sought in a WINDOW rather than on a single line:
#
#     <style                                                  <- element
#       id="antd"
#       dangerouslySetInnerHTML={{ __html: extractStyle(c) }}  <- attribute
#     />
#
# Four lines back covers attribute-per-line formatting without reaching the
# previous sibling element.
_LOOKBACK = 4


def is_framework_style_injection(
    line: str, lines: list[str] | None = None, line_num: int = 0
) -> bool:
    """True when this line injects framework-extracted CSS into ``<style>``.

    ``line_num`` is 1-based. Pass ``lines``/``line_num`` to resolve the
    multi-line JSX form; without them only the single-line form is detected.
    """
    if not _CSS_SOURCE.search(line):
        return False
    if _STYLE_ELEMENT.search(line):
        return True
    if not lines or line_num <= 0:
        return False
    lo = max(0, line_num - 1 - _LOOKBACK)
    for text in reversed(lines[lo:line_num - 1]):
        if _STYLE_ELEMENT.search(text):
            return True
        # A tag closed in between: the <style> found belongs to another element.
        if "/>" in text or "</" in text:
            return False
    return False
