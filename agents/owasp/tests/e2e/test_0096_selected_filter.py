"""E2E: the category filter a mapping-mode result carries (feature 0096).

In mapping mode the agent does not apply the audit's ``categories`` filter
itself: it hands it to the backend as ``mapping.selected``, and the backend
narrows every finding's labels to it. The backend validates a mapping all or
nothing, so one entry that is not a category id would discard the whole
mapping and label nothing. The contract pinned here:

- ``selected`` is the EFFECTIVE filter: only the edition's own category ids,
  in the order given, each once. Anything else in ``categories`` (another
  agent's vocabulary, a lowercase id, a non-string, an id the edition does not
  have) is dropped with a notice that does not echo it;
- a non-empty filter with no usable id left selects NOTHING — never ``[]``,
  which means "all" — in a form the backend accepts;
- mapping mode therefore labels exactly the (finding, category) pairs the
  legacy answer copies for the same config, and scores the same way;
- no filter value, however malformed, stops the run: the stream always ends
  with a result and ``agent_end status=completed`` (feature 0063).
"""

import json
import pathlib
import re

import pytest

from owasp_agent.agent import run_audit
from shared.audit_runner import compute_score
from shared.owasp.mapping import load_edition

_FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures"
_GOLDEN = json.loads((_FIXTURES / "owasp_0096_legacy_stream.json").read_text("utf-8"))

# The backend's grammar for a `selected` entry (mappingCategoryRe).
_CATEGORY_ID = re.compile(r"^A\d{2}$")


def _events(chunks):
    out = []
    for chunk in chunks:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _priors():
    return json.loads(json.dumps(_GOLDEN["priors"]))


def _run(config, priors, mapping=True):
    return _events(run_audit("e2e-0096-sel", "/unused", dict(config), prior_findings=priors,
                             accepts_mapping=1 if mapping else None))


def _result(events):
    return next(d for t, d in events if t == "result")


def _thinking(events):
    return "\n".join(d.get("content", "") for t, d in events if t == "thinking")


def _edition_ids(edition_id):
    return {c.id for c in load_edition(edition_id).categories}


def _labels_from_mapping(result, priors):
    """The (file, line, category) pairs the backend would label from a mapping.

    The backend validates a mapping all or nothing: one `selected` entry off
    its grammar rejects the mapping, and nothing is labelled.
    """
    mapping = result["mapping"]
    selected = mapping["selected"]
    if not all(isinstance(s, str) and _CATEGORY_ID.match(s) for s in selected):
        return []
    out = []
    for p in priors:
        if not isinstance(p, dict):
            continue
        for c in mapping["table"].get(str(p.get("category", "")), []):
            if not selected or c["id"] in selected:
                out.append((p.get("file_path"), p.get("line_start"), c["id"]))
    return sorted(out)


def _copies_from_legacy(result):
    return sorted((f.get("file_path"), f.get("line_start"), f["owasp_category_id"])
                  for f in result["findings"])


@pytest.mark.parametrize("categories, selected", [
    (["A07", "retry"], ["A07"]),
    (["A05", "injection", "A07", "A05"], ["A05", "A07"]),
    (["A07", "a05", " A05", "A11"], ["A07"]),
    (["A07", 7, None, {"id": "A05"}, ["A05"]], ["A07"]),
])
def test_selected_is_the_effective_filter(categories, selected):
    result = _result(_run({"edition": "2025", "categories": categories}, _priors()))
    assert result["mapping"]["selected"] == selected


@pytest.mark.parametrize("categories", [
    ["retry"],
    ["a07"],
    ["A11", "A00"],
    [7, None],
    [["A07"]],
    "A07",
    7,
    {"A07": True},
])
def test_filter_with_no_usable_id_selects_nothing(categories):
    events = _run({"edition": "2025", "categories": categories}, _priors())
    result = _result(events)
    selected = result["mapping"]["selected"]
    assert selected, "a non-empty filter must never collapse to [] (= all)"
    assert all(isinstance(s, str) and _CATEGORY_ID.match(s) for s in selected), selected
    assert not set(selected) & _edition_ids("2025"), "selects none of the edition"
    assert _labels_from_mapping(result, _priors()) == []
    assert result["score"] == 100.0
    assert result["findings"] == []
    assert next(d for t, d in events if t == "agent_end")["status"] == "completed"


@pytest.mark.parametrize("categories", [
    ["A07", 7], [None], [7], [["A07"]], "A07", 7, {"A07": True}, [{"id": "A07"}],
])
def test_malformed_filter_never_stops_the_run(categories):
    events = _run({"edition": "2025", "categories": categories}, _priors())
    types = [t for t, _ in events]
    assert types[0] == "agent_start" and types[-1] == "agent_end"
    assert "result" in types
    assert next(d for t, d in events if t == "agent_end")["status"] == "completed"


def test_every_selected_entry_passes_the_backend_grammar():
    for categories in (["A07", "retry"], ["retry"], ["A07", "a05", 3, "A07"]):
        selected = _result(_run({"categories": categories}, _priors()))["mapping"]["selected"]
        assert all(isinstance(s, str) and _CATEGORY_ID.match(s) for s in selected), selected


def test_dropped_entries_are_noticed_but_not_echoed():
    junk = "x" * 5000
    events = _run({"edition": "2025", "categories": ["A07", junk, "retry"]}, _priors())
    text = _thinking(events)
    assert junk not in text and "retry" not in text
    assert re.search(r"\b2 \b.*categor", text), text
    assert _result(events)["mapping"]["selected"] == ["A07"]


def test_valid_filter_raises_no_notice():
    events = _run({"edition": "2025", "categories": ["A07"]}, _priors())
    assert "ignored" not in _thinking(events).lower()


@pytest.mark.parametrize("config", [
    {"edition": "2025", "categories": ["A07", "retry"]},
    {"edition": "2025", "categories": ["retry"]},
    {"edition": "2025", "categories": ["a07", "A05"]},
    {"edition": "2025", "categories": ["A05", "A11"]},
    {"edition": "2021", "categories": ["A03", "bogus", "A07"]},
    {"edition": "2025", "categories": []},
    {"edition": "2025"},
])
def test_mapping_labels_what_legacy_copies(config):
    priors = _priors()
    mapped = _result(_run(config, priors))
    legacy = _result(_run(config, priors, mapping=False))
    assert _labels_from_mapping(mapped, priors) == _copies_from_legacy(legacy)


def test_mixed_filter_scores_only_the_valid_ids():
    priors = [
        {"category": "CWE-798", "severity": "high", "file_path": "a.py", "line_start": 1},
        {"category": "CWE-89", "severity": "critical", "file_path": "b.py", "line_start": 2},
    ]
    mixed = _result(_run({"edition": "2025", "categories": ["A07", "retry"]}, priors))
    only = _result(_run({"edition": "2025", "categories": ["A07"]}, priors))
    assert mixed["score"] == only["score"] == compute_score([priors[0]], 2)
