"""Unit: the OWASP score in mapping mode (feature 0096).

In mapping mode the agent emits no findings, so its score cannot be computed
over emitted rows as in legacy mode (one row per prior AND category). It is
``compute_score`` over the DISTINCT priors that map to at least one SELECTED
category — one entry per prior however many categories it maps to, an exact
repeat of a prior counted once — against the number of priors received. It is
a pre-dedup figure: the agent never sees the backend's final finding set.
"""

import json

import pytest

import owasp_agent.agent as agent_mod
from shared.audit_runner import compute_score
from shared.owasp.mapping import Category, Edition


def _events(gen):
    out = []
    for chunk in gen:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _score(config, priors):
    events = _events(agent_mod.run_audit("u-0096", "/s", dict(config), prior_findings=priors,
                                         accepts_mapping=1))
    return next(d for t, d in events if t == "result")["score"]


def _cwe(cwe, severity="high", path="app.py", line=10, title=None):
    return {"category": f"CWE-{cwe}", "title": title or f"weakness {cwe}",
            "severity": severity, "file_path": path, "line_start": line,
            "line_end": line, "description": "d", "check_id": f"cwe.x.{cwe}"}


# A two-category CWE. No shipped edition maps one CWE twice, but the edition
# format allows it, and "one per prior" is exactly the rule that case tests.
_FAKE = Edition(
    edition_id="2099",
    title="Fake",
    categories=(
        Category("A01", "A01-one", "One", frozenset({1, 12}), "https://example.test/a01"),
        Category("A02", "A02-two", "Two", frozenset({12, 2}), "https://example.test/a02"),
        Category("A03", "A03-three", "Three", frozenset({3}), "https://example.test/a03"),
    ),
)


@pytest.fixture
def fake_edition(monkeypatch):
    monkeypatch.setattr(agent_mod, "load_edition", lambda edition_id=None: _FAKE)


def test_prior_mapping_to_two_categories_counts_once(fake_edition):
    priors = [_cwe(12, "critical")]
    assert _score({}, priors) == compute_score(priors, 1)
    # Legacy mode counts it once per category: the two differ, by design.
    legacy = _events(agent_mod.run_audit("u", "/s", {}, prior_findings=priors))
    assert next(d for t, d in legacy if t == "result")["score"] == compute_score(
        [priors[0], priors[0]], 2)


def test_exact_repeats_count_once(fake_edition):
    a = _cwe(1, "high")
    priors = [a, dict(a), dict(a)]
    assert _score({}, priors) == compute_score([a], 3)


def test_distinct_sites_each_count(fake_edition):
    priors = [_cwe(1, "high", line=1), _cwe(1, "high", line=2),
              _cwe(1, "high", line=2, title="other title")]
    assert _score({}, priors) == compute_score(priors, 3)


def test_only_priors_in_a_selected_category_count(fake_edition):
    in_a01 = _cwe(1, "critical")
    in_a03 = _cwe(3, "critical", path="b.py")
    in_both = _cwe(12, "medium", path="c.py")
    priors = [in_a01, in_a03, in_both]
    assert _score({"categories": ["A01"]}, priors) == compute_score([in_a01, in_both], 3)
    assert _score({"categories": ["A03"]}, priors) == compute_score([in_a03], 3)
    assert _score({"categories": ["A02"]}, priors) == compute_score([in_both], 3)
    assert _score({}, priors) == compute_score(priors, 3)


def test_unmapped_and_uncategorised_priors_do_not_count(fake_edition):
    mapped = _cwe(3, "high")
    priors = [mapped, _cwe(999, "critical", path="u.py"),
              {"category": "retry", "severity": "critical", "file_path": "r.py"},
              {"category": "", "severity": "critical"}, "not-a-dict", None]
    assert _score({}, priors) == compute_score([mapped], len(priors))


def test_nothing_mapped_scores_100(fake_edition):
    assert _score({}, []) == 100.0
    assert _score({"categories": ["A03"]}, [_cwe(1, "critical")]) == 100.0


def test_real_edition_score(monkeypatch):
    """The same rule on a shipped edition (2025: 89->A05, 798->A07, 918->A01)."""
    sqli = _cwe(89, "critical", path="db.py")
    secret = _cwe(798, "high", path=".env")
    ssrf = _cwe(918, "high", path="net.py")
    priors = [sqli, secret, dict(secret), ssrf]
    assert _score({"edition": "2025"}, priors) == compute_score([sqli, secret, ssrf], 4)
    assert _score({"edition": "2025", "categories": ["A05", "A07"]}, priors) == compute_score(
        [sqli, secret], 4)


# A prior's severity is scored with the default the legacy answer gives it
# (`medium`), whatever shape it arrives in; a bad severity never raises.
@pytest.mark.parametrize("severity", [None, "", "MISSING", 7, ["high"]])
def test_bad_severity_scores_as_medium(fake_edition, severity):
    prior = {"category": "CWE-1", "file_path": "a.py", "line_start": 1}
    if severity != "MISSING":
        prior["severity"] = severity
    expected = compute_score([{**prior, "severity": "medium"}], 1)
    assert _score({}, [prior]) == expected


@pytest.mark.parametrize("severity", [None, "", "MISSING"])
def test_bad_severity_scores_like_legacy(fake_edition, severity):
    prior = {"category": "CWE-3", "file_path": "a.py", "line_start": 1}
    if severity != "MISSING":
        prior["severity"] = severity
    legacy = _events(agent_mod.run_audit("u", "/s", {}, prior_findings=[prior]))
    assert _score({}, [prior]) == next(d for t, d in legacy if t == "result")["score"]
