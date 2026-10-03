"""E2E: the mapping result the OWASP agent returns in mapping mode (feature 0096).

In mapping mode the agent does not re-emit CWE findings as OWASP rows. It
returns the edition's CWE->category TABLE and the backend labels the final,
deduplicated finding set by `category`. The contract pinned here:

- ``table`` is the FULL edition table — every CWE the edition maps (2025: 249,
  2021: 196) — whatever ``categories`` the audit selected, because the backend
  keeps lineage labels across category subsets;
- each table entry is ``{"id", "name"}`` and nothing else;
- ``selected`` echoes the effective ``categories`` filter (``[]`` = all);
- the ``owasp_coverage`` manifest is identical to the legacy answer's for the
  same priors (compared against the pre-0096 golden capture);
- the mapping is present, full table included, even with no priors at all;
- no source text travels in it (0096 I6).

It also guards ``owasp_0096_mapping_stream.json``, the real agent payload the
backend flow test replays: if the agent's output drifts from it, this fails.
"""

import json
import pathlib
import re

import pytest

from owasp_agent.agent import run_audit
from shared.owasp.mapping import load_edition

_FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures"
_GOLDEN = json.loads((_FIXTURES / "owasp_0096_legacy_stream.json").read_text("utf-8"))

_EDITION_SIZES = {"2025": 249, "2021": 196}


def _events(chunks):
    out = []
    for chunk in chunks:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _result(config, priors, run_id="e2e-0096-map"):
    events = _events(run_audit(run_id, "/unused", dict(config), prior_findings=priors,
                               accepts_mapping=1))
    return next(d for t, d in events if t == "result")


def _priors():
    return json.loads(json.dumps(_GOLDEN["priors"]))


def _expected_table(edition_id):
    """The edition's own CWE->categories relation, read from the shared data."""
    edition = load_edition(edition_id)
    table = {}
    for cat in edition.categories:
        for cwe in sorted(cat.cwes):
            table.setdefault(f"CWE-{cwe}", []).append({"id": cat.id, "name": cat.name})
    return table


@pytest.mark.parametrize("edition", sorted(_EDITION_SIZES))
def test_table_is_the_full_edition(edition):
    mapping = _result({"edition": edition}, _priors())["mapping"]
    assert mapping["version"] == 1
    assert mapping["framework"] == "owasp"
    assert mapping["edition"] == edition
    assert len(mapping["table"]) == _EDITION_SIZES[edition]
    assert mapping["table"] == _expected_table(edition)


@pytest.mark.parametrize("edition", sorted(_EDITION_SIZES))
@pytest.mark.parametrize("categories", [["A07"], ["A01", "A05"], []])
def test_table_is_independent_of_the_categories_filter(edition, categories):
    full = _result({"edition": edition}, _priors())["mapping"]["table"]
    subset = _result({"edition": edition, "categories": categories}, _priors())["mapping"]
    assert subset["table"] == full
    assert len(subset["table"]) == _EDITION_SIZES[edition]


@pytest.mark.parametrize("edition", sorted(_EDITION_SIZES))
def test_table_entries_are_id_and_name_only(edition):
    table = _result({"edition": edition}, [])["mapping"]["table"]
    for key, cats in table.items():
        assert re.fullmatch(r"CWE-\d{1,5}", key), key
        assert isinstance(cats, list) and cats, key
        for c in cats:
            assert set(c) == {"id", "name"}, (key, c)
            assert re.fullmatch(r"A\d{2}", c["id"]), (key, c)
            assert isinstance(c["name"], str) and 0 < len(c["name"]) <= 120


@pytest.mark.parametrize("config, selected", [
    ({"edition": "2025"}, []),
    ({"edition": "2025", "categories": []}, []),
    ({"edition": "2025", "categories": ["A07"]}, ["A07"]),
    ({"edition": "2021", "categories": ["A03", "A07"]}, ["A03", "A07"]),
])
def test_selected_echoes_the_config(config, selected):
    assert _result(config, _priors())["mapping"]["selected"] == selected


def test_unknown_edition_maps_against_the_fallback():
    result = _result({"edition": "1999"}, _priors())
    fallback = load_edition().edition_id
    assert result["mapping"]["edition"] == fallback
    assert result["owasp_coverage"]["edition"] == fallback
    assert len(result["mapping"]["table"]) == _EDITION_SIZES[fallback]


@pytest.mark.parametrize("name", sorted(_GOLDEN["cases"]))
def test_coverage_manifest_matches_legacy_mode(name):
    """Same priors, same config: the manifest is the pre-0096 manifest."""
    case = _GOLDEN["cases"][name]
    priors = _priors() if case["use_priors"] else []
    legacy = next(d for t, d in _events(case["stream"]) if t == "result")
    mapped = _result(dict(case["config"]), priors, run_id=f"golden-{name}")
    assert mapped["owasp_coverage"] == legacy["owasp_coverage"]


@pytest.mark.parametrize("edition", sorted(_EDITION_SIZES))
def test_empty_priors_still_return_the_full_table(edition):
    result = _result({"edition": edition, "cwe_stage_status": "absent"}, [])
    assert result["findings"] == []
    assert len(result["mapping"]["table"]) == _EDITION_SIZES[edition]
    assert result["mapping"]["selected"] == []
    assert result["owasp_coverage"]["cwe_stage_status"] == "absent"
    assert result["score"] == 100.0


def test_mapping_carries_no_source_text():
    priors = _priors()
    mapping = json.dumps(_result({"edition": "2025"}, priors)["mapping"])
    for p in priors:
        if not isinstance(p, dict):
            continue
        for field in ("title", "description", "file_path", "check_id"):
            value = p.get(field)
            # Short values ("d") occur in any JSON by chance; the fixture's
            # identifying texts are all longer than that.
            if value and len(value) >= 6:
                assert value not in mapping, f"prior {field} {value!r} leaked into the mapping"
    assert "SECRET=abc" not in mapping


# --- the backend flow fixture ----------------------------------------------


def test_backend_flow_fixture_is_the_real_agent_payload():
    """``backend/test/e2e/owasp_mapping_flow_test.go`` replays this stream.

    Regenerate with ``tests/fixtures/regen_owasp_0096_mapping_stream.py`` after
    an intended change to the agent's output, then re-run the backend test.
    """
    fx = json.loads((_FIXTURES / "owasp_0096_mapping_stream.json").read_text("utf-8"))
    # H1: the capability is a top-level /run field, never a config key.
    assert fx["accepts_mapping"] == 1 and "accepts_mapping" not in fx["config"]
    fresh = "".join(run_audit(fx["run_id"], "/unused", dict(fx["config"]),
                              prior_findings=json.loads(json.dumps(fx["priors"])),
                              accepts_mapping=fx["accepts_mapping"]))
    assert fresh == fx["stream"], (
        "the OWASP agent's mapping-mode output drifted from the backend flow "
        "fixture; regenerate it with tests/fixtures/regen_owasp_0096_mapping_stream.py"
    )
    events = _events(b + "\n\n" for b in fx["stream"].split("\n\n") if b.strip())
    assert "finding" not in [t for t, _ in events]
    result = next(d for t, d in events if t == "result")
    assert result["findings"] == [] and result["mapping"]["selected"] == ["A05", "A07"]
