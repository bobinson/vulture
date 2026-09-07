"""`_fill` substitutes in one pass: a variable's VALUE is never template.

Feature 0089. `_fill` was a sequential `str.replace` over `spec.variables`,
which rescans text it has already substituted. A value containing a later key's
placeholder was therefore expanded as if it were part of the template.

Found by adversarial review of the DISCOVER cutover, and reachable there:
`shared/discovery/helpers.py` does `site.technologies.append(f"Server: {server}")`
with `server` the scanned target's raw `Server` header, so a target answering
`Server: {framework_hints}` could splice another variable's contents into its own
line of the prompt. 10 of the 20 ordered pairs of discover's five variables
diverged from `str.format`, every one a forward reference.

It does not widen egress — both sides of the substitution are the same target's
own bytes, and the header already appears on the `Response headers:` line — but a
value must never be able to act as template, and the `.format()` call the flip
replaced did not allow it.
"""

from __future__ import annotations

import pytest

from shared.prompt.render import _fill


def test_a_value_containing_a_later_placeholder_is_not_expanded():
    """The defect, stated minimally. Dict order puts `a` before `b`."""
    out = _fill("A: {a}\nB: {b}", {"a": "x{b}y", "b": "SECRET"})
    assert out == "A: x{b}y\nB: SECRET"
    assert "x SECRET y".replace(" ", "") not in out
    assert out.count("SECRET") == 1, "the value must not be re-substituted"


def test_the_defect_is_order_independent():
    """A BACKWARD reference was never vulnerable; a forward one was.

    Both directions are asserted so the fix cannot be mistaken for a reordering
    of the dict, which would only move the hole.
    """
    fwd = _fill("{a}|{b}", {"a": "<{b}>", "b": "B"})
    bwd = _fill("{a}|{b}", {"b": "<{a}>", "a": "A"})
    assert fwd == "<{b}>|B"
    assert bwd == "A|<{a}>"


def test_it_matches_str_format_wherever_format_is_defined():
    """One pass, same result as `.format` — on input `.format` can express.

    `.format` needs literal braces doubled, so this compares only on values
    without them; that is exactly the domain where the two must not differ.
    """
    tmpl = "t={technologies} e={api_endpoints} f={forms}"
    vals = {"technologies": "nginx", "api_endpoints": "/api/x", "forms": "POST /a"}
    assert _fill(tmpl, vals) == tmpl.format(**vals)


def test_literal_braces_survive_which_is_why_this_is_not_str_format():
    """A JSON exemplar must pass through untouched.

    This is the reason `_fill` exists at all: `.format` would raise on these, and
    doubling them in the fragment is what produced defects #6 and #7 — a fragment
    recording the encoding of a prompt rather than the prompt.
    """
    tmpl = 'Return ONLY: {"endpoints": ["/a"], "reasoning": "why"}\nPath: {path}'
    out = _fill(tmpl, {"path": "/tmp/x"})
    assert '{"endpoints": ["/a"], "reasoning": "why"}' in out
    assert out.endswith("Path: /tmp/x")
    with pytest.raises((KeyError, IndexError, ValueError)):
        tmpl.format(path="/tmp/x")  # the reason we cannot just use .format


def test_an_unknown_placeholder_is_left_verbatim_not_raised():
    """A fragment may name a variable a different call site supplies.

    Parity tests and `check_09_placeholder_echo` catch a genuinely unfilled one;
    raising here would make a spec unrenderable in the lint sweep, which
    supplies no variables at all.
    """
    assert _fill("{known} {unknown}", {"known": "K"}) == "K {unknown}"


def test_no_variables_is_the_identity():
    tmpl = "nothing to fill {x}"
    assert _fill(tmpl, {}) is tmpl or _fill(tmpl, {}) == tmpl


def test_the_discover_pairs_that_actually_diverged():
    """The measured case, with discover's real variable names and emission order.

    Regression-guards the specific reachable path: a target-supplied
    `technologies` value carrying `{headers}`.
    """
    order = ("technologies", "api_endpoints", "forms", "headers", "framework_hints")
    tmpl = "\n".join(f"{k}: {{{k}}}" for k in order)
    vals = dict.fromkeys(order, "-")
    vals["technologies"] = "Server: {framework_hints}"
    vals["framework_hints"] = "PWNED"
    out = _fill(tmpl, vals)
    assert "technologies: Server: {framework_hints}" in out
    assert out.count("PWNED") == 1, "the target's header must not pull in another variable"
