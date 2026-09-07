"""`as_fragment_text` — read a `str.format` template the way a fragment must.

Feature 0089. A prompt that reaches the model through `str.format` writes a
literal brace as `{{` in its source. `render._fill` is a plain `{name}` -> value
replace and deliberately NOT `str.format`: a format-based fill would raise on
any prompt containing a JSON brace, which is most of them. So in fragment syntax
`{{` is two literal braces.

A fragment that copies the source literal verbatim therefore records the
ENCODING of the prompt rather than the prompt, and after the call-site cutover
it would ship `{{` to the model inside the JSON exemplar — the one place the
output contract has to be exact. That defect shipped in `discover/suggest` and in
all 13 `prove/*` fragments, and every pin comparing raw-literal to raw-fragment
agreed with it, because both sides carried the escape.

Binding every placeholder to itself resolves exactly the escaping and leaves the
template a template, so a pin stays a single source of truth and a byte equality.
"""

from __future__ import annotations

import string


def as_fragment_text(live_template: str) -> str:
    names = {n for _, n, _, _ in string.Formatter().parse(live_template) if n}
    return live_template.format(**{n: "{" + n + "}" for n in names})
