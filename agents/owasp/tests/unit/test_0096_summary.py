"""Unit: the mapping-mode summary and the unknown-edition notice (feature 0096).

Summary (M11). "Mapped N finding(s) into k/T categories" counts in ``k`` only
the categories that are both SELECTED and found, and ``T`` is the size of the
audit's universe — the selected categories of the edition, or every category
of the edition when nothing is selected. It was ``found-in-any-category/10``:
wrong for a category filter (k counted unselected categories) and for any
edition that does not have exactly ten categories.

The LEGACY summary is deliberately untouched: the legacy answer is pinned byte
for byte against the 0063 golden (``test_0096_negotiation.py``) because a
pre-0096 backend reads it.

Notice (L5). An unknown edition is echoed in a notice, but the value is
arbitrary audit input: it is truncated to 32 characters and ``repr``-quoted so
it can neither flood the stream nor inject a line.
"""

import json

import pytest

import owasp_agent.agent as agent_mod
from shared.owasp.mapping import Category, Edition


def _events(gen):
    out = []
    for chunk in gen:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _run(config, priors, accepts_mapping=1):
    return _events(agent_mod.run_audit("u-sum", "/s", dict(config), prior_findings=priors,
                                       accepts_mapping=accepts_mapping))


def _summary(config, priors, accepts_mapping=1):
    return next(d for t, d in _run(config, priors, accepts_mapping) if t == "result")["summary"]


def _cwe(cwe, path="app.py"):
    return {"category": f"CWE-{cwe}", "title": f"w{cwe}", "severity": "high",
            "file_path": path, "line_start": 1, "line_end": 1, "description": "d"}


_FAKE = Edition(
    edition_id="2099",
    title="Fake",
    categories=(
        Category("A01", "A01-one", "One", frozenset({1}), "https://example.test/a01"),
        Category("A02", "A02-two", "Two", frozenset({2}), "https://example.test/a02"),
        Category("A03", "A03-three", "Three", frozenset({3}), "https://example.test/a03"),
    ),
)


@pytest.fixture
def fake_edition(monkeypatch):
    monkeypatch.setattr(agent_mod, "load_edition", lambda edition_id=None: _FAKE)


def test_denominator_is_the_edition_size_not_ten(fake_edition):
    summary = _summary({}, [_cwe(1), _cwe(2)])
    assert "into 2/3 OWASP Top 10:2099 categories" in summary, summary


def test_only_selected_found_categories_count(fake_edition):
    # A01 and A02 are found, but only A02 and A03 are selected.
    summary = _summary({"categories": ["A02", "A03"]}, [_cwe(1), _cwe(2)])
    assert "Mapped 1 finding(s) into 1/2 " in summary, summary


def test_filter_selecting_nothing_counts_nothing(fake_edition):
    summary = _summary({"categories": ["A99"]}, [_cwe(1), _cwe(2)])
    assert "Mapped 0 finding(s) into 0/0 " in summary, summary


def test_real_edition_selected_filter():
    priors = [_cwe(89), _cwe(798), _cwe(918)]  # 2021: A03, A07, A10
    summary = _summary({"edition": "2021", "categories": ["A03", "A07"]}, priors)
    assert "Mapped 2 finding(s) into 2/2 OWASP Top 10:2021 categories." in summary, summary


def _notices(config, accepts_mapping):
    return [d["content"] for t, d in _run(config, [_cwe(89)], accepts_mapping)
            if t == "thinking" and d["content"].startswith("Unknown OWASP edition")]


@pytest.mark.parametrize("accepts_mapping", [1, None])
def test_unknown_edition_echo_is_bounded(accepts_mapping):
    [notice] = _notices({"edition": "Z" * 5000}, accepts_mapping)
    assert "Z" * 32 in notice and "Z" * 33 not in notice
    assert len(notice) < 120


@pytest.mark.parametrize("accepts_mapping", [1, None])
def test_unknown_edition_echo_is_repr_safe(accepts_mapping):
    [notice] = _notices({"edition": "x\n\r evil"}, accepts_mapping)
    assert "\n" not in notice and "\r" not in notice and " " not in notice


@pytest.mark.parametrize("accepts_mapping", [1, None])
def test_unknown_non_string_edition_echo_is_bounded(accepts_mapping):
    [notice] = _notices({"edition": ["A" * 100] * 1000}, accepts_mapping)
    assert len(notice) < 120


def test_short_unknown_edition_echo_is_unchanged():
    """The legacy golden's `'1999'` notice must stay byte-identical."""
    [notice] = _notices({"edition": "1999"}, None)
    assert notice == "Unknown OWASP edition '1999'; falling back to 2025."
