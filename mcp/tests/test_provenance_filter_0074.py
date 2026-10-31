"""Feature 0074 P2a/P2b: provenance filter on the MCP tool vulture_get_findings.

Plan section 5.6 item 3, AC39 and AC10. `vulture_get_findings(provenance=...)`
takes the vocabulary the UI and the findings API take:

- an exact provenance ("skill", "llm", "llm_l5_verified", "semgrep") matches
  that provenance literally;
- "llm_family" matches every finding whose provenance, trimmed and
  lower-cased, starts with "llm" (the one family rule: Go isLLMProvenance,
  Python _is_deterministic), so "LLM" and " llm " are members; the filter
  value itself is exact and case-sensitive ("LLM_FAMILY" selects nothing);
- "both" matches findings whose validation.provenance_origins spans the skill
  family and the LLM family;
- no provenance argument returns every finding, as today.

All three surfaces read ONE fixture,
backend/internal/handler/testdata/provenance_filter_cases_0074.json, so they
select the same rows (AC39). The backend mock below answers with EVERY finding
whatever query it is sent: the MCP server must select the rows itself, as it
does for severity and category, so a backend that predates the server-side
filter (and ignores the parameter) still yields the right answer. The filter
never changes a finding's validation_status or validation blob (AC10).
Malformed provenance_origins values in the fixture (a string, an object, null,
non-string or blank entries) are "not both" and must not raise. An unknown
value, or a different casing of a vocabulary word, selects nothing.

HOW TO RUN. `make test-mcp` (the CI test-mcp job runs the same target).
mcp/tests needs `mcp` (1.x; 2.x renames FastMCP and breaks the server.py
import), `respx` and `pytest-asyncio`, none of which the agents venv carries.
"""
import json
import pathlib

import httpx
import pytest
import respx

_FIXTURE = (pathlib.Path(__file__).resolve().parents[2]
            / "backend/internal/handler/testdata/provenance_filter_cases_0074.json")
_CASES = json.loads(_FIXTURE.read_text())
_FAMILY = json.loads((_FIXTURE.parent / "llm_provenance_family_0074.json").read_text())
_BASE = "http://localhost:28080/api/audits/a0074"


def _mock_audit(findings: list | None = None, **audit_fields):
    audit = {"id": "a0074", "status": "completed",
             "findings": _CASES["findings"] if findings is None else findings, **audit_fields}
    route = respx.get(_BASE).mock(return_value=httpx.Response(200, json=audit))
    respx.get(_BASE + "/lineage").mock(return_value=httpx.Response(200, json=[]))
    return route


async def _fetch(**kwargs) -> dict:
    from server import vulture_get_findings
    return await vulture_get_findings(audit_id="a0074", limit=100, **kwargs)


def _fingerprints(result: dict) -> list[str]:
    return sorted(f["fingerprint"] for f in result["findings"])


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("value", sorted(_CASES["expect"]))
async def test_provenance_filter_selects_the_shared_fixture_rows(value):
    """AC39: each value selects exactly the rows the API and the UI select."""
    _mock_audit()
    result = await _fetch(provenance=value)
    want = sorted(_CASES["expect"][value])
    assert _fingerprints(result) == want
    assert result["total"] == len(want)


_NOT_BOTH = sorted({f["fingerprint"] for f in _CASES["findings"]} - set(_CASES["expect"]["both"]))


@respx.mock
@pytest.mark.asyncio
async def test_malformed_or_one_family_origins_are_not_both():
    """AC39 parity: empty/blank tiers, one-family pairs, and origins that are a
    string, an object, null, absent or non-string entries are not "both" and
    never fail the call, the same verdict the API and the UI reach on the
    shared fixture. Pinned per row so a regression names the edge case."""
    _mock_audit()
    got = set(_fingerprints(await _fetch(provenance="both")))
    assert got, "both selected nothing; the per-row check would be vacuous"
    assert [fp for fp in _NOT_BOTH if fp in got] == []


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("value", sorted(_CASES["expect"]))
async def test_filter_never_changes_validation(value):
    """AC10: a row's validation_status, confidence and validation blob are the
    same through the filter as without it (and the filter returns its rows, so
    the check is never vacuous)."""
    _mock_audit()
    base = {f["fingerprint"]: f for f in (await _fetch())["findings"]}
    served = (await _fetch(provenance=value))["findings"]
    assert len(served) == len(_CASES["expect"][value])
    keys = ("validation_status", "validation_confidence", "validation")
    assert [{k: f.get(k) for k in keys} for f in served] == \
        [{k: base[f["fingerprint"]].get(k) for k in keys} for f in served]


@respx.mock
@pytest.mark.asyncio
async def test_provenance_combines_with_severity():
    """AC39: provenance is one more AND-ed predicate beside the existing ones."""
    _mock_audit()
    family = set(_CASES["expect"]["llm_family"])
    want = sorted(f["fingerprint"] for f in _CASES["findings"]
                  if f["fingerprint"] in family and f["severity"] == "high")
    assert want, "the fixture has no high llm_family row; the check would be vacuous"
    result = await _fetch(provenance="llm_family", severity="high")
    assert _fingerprints(result) == want


@respx.mock
@pytest.mark.asyncio
async def test_no_provenance_returns_every_finding():
    """Regression pin (passes before 0074): no argument, no filtering."""
    _mock_audit()
    result = await _fetch()
    assert result["total"] == len(_CASES["findings"])


def test_get_findings_advertises_the_provenance_vocabulary():
    """AC39: an MCP caller can discover the filter: `provenance` is a tool
    parameter and the description names llm_family and both."""
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    tool = tools["vulture_get_findings"]
    assert "provenance" in tool.parameters["properties"]
    # Quoted tokens: "both" is an ordinary English word, so bare prose would
    # satisfy an unquoted check.
    assert '"llm_family"' in tool.description and '"both"' in tool.description


# --- 0074 fix round -------------------------------------------------------


@pytest.mark.parametrize("case", _FAMILY, ids=lambda c: repr(c["provenance"]))
def test_llm_family_rule_matches_the_shared_family_fixture(case):
    """#7: the MCP copy of the ONE family rule agrees with Go and Python on the
    prefix-vs-substring rows (skill_llm, semgrep-llm, llmfoo), as a provenance
    and as an origin beside a deterministic one."""
    import server
    assert server._is_llm_family({"provenance": case["provenance"]}) is case["is_llm"]
    beside = {"validation": {"provenance_origins": ["signature", case["provenance"]]}}
    assert server._spans_both_families(beside) is case["is_llm"]


@pytest.mark.parametrize("origins,both", [
    (["llm", "catalog_rollup"], False),
    ([" CATALOG_ROLLUP ", "llm_l5_verified"], False),
    (["catalog_rollup", "skill"], False),
    (["catalog_rollup", "skill", "llm"], True),
])
def test_grouping_provenance_is_not_a_tier(origins, both):
    """#11 (C11): catalog_rollup is neither family in the both computation."""
    import server
    assert server._spans_both_families({"validation": {"provenance_origins": origins}}) is both


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["llm_family", "both", "skill"])
async def test_provenance_is_forwarded_to_the_api(value):
    """#39: the filter is sent as ?provenance= so a current backend filters
    server side; the local predicate still runs for an older backend that
    ignores it (the mock answers every row, and the result is still exact)."""
    route = _mock_audit()
    result = await _fetch(provenance=value)
    assert route.calls.last.request.url.params.get("provenance") == value
    assert _fingerprints(result) == sorted(_CASES["expect"][value])


@respx.mock
@pytest.mark.asyncio
async def test_no_provenance_sends_no_query_parameter():
    """#39: without a filter the request is unchanged."""
    route = _mock_audit()
    await _fetch()
    assert "provenance" not in route.calls.last.request.url.params


_LEGACY_ROWS = [{k: v for k, v in f.items() if k != "validation"} for f in _CASES["findings"][:3]]


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("audit_fields,rows,recorded", [
    ({}, _LEGACY_ROWS, False),
    ({"origins_recorded": False}, [], False),
    ({"origins_recorded": True}, [], True),
    ({}, None, True),
    ({}, [{"fingerprint": "fp-null", "validation": {"provenance_origins": None}}], True),
])
async def test_both_says_whether_origins_were_recorded(audit_fields, rows, recorded):
    """#35: an empty "both" on an audit whose findings carry no
    provenance_origins means "not recorded", not "never corroborated". The
    API's origins_recorded flag wins; without it the rows decide."""
    _mock_audit(rows, **audit_fields)
    result = await _fetch(provenance="both")
    assert result["origins_recorded"] is recorded
    assert ("note" in result) is (not recorded)


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, "llm_family"])
async def test_only_both_carries_the_origins_marker(value):
    """#35: the marker qualifies "both" only; other calls keep their shape."""
    _mock_audit()
    assert "origins_recorded" not in await _fetch(**({"provenance": value} if value else {}))
