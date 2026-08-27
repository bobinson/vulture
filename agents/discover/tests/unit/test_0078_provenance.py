"""Feature 0078 track C (AC12.1) — discover's delta and snapshot provenance agree.

The discover agent does not route through ``run_combined_audit``, so the
``_finalize_finding_inplace`` stamp that gives every other scanning agent its
per-finding provenance never runs here. ``run_discover`` emits each finding
twice: once as a per-finding ``finding`` delta (which the backend rescues
verbatim when an agent is cut off before its snapshot) and once inside the
``result`` snapshot. Those two renderings of the same row must not disagree
about provenance, or the persisted value depends on whether the agent was
truncated — and an empty provenance silently disables the cross-agent dedup
guard (``VULTURE_DEDUP_PREFER_DETERMINISTIC``), which arbitrates on it.
"""

from __future__ import annotations

import json
from typing import Any

import discover_agent.agent as agent_mod
import pytest
from shared.discovery.sitemap import SiteMap


def _events(sse: list[str], want: str) -> list[dict[str, Any]]:
    """Return the decoded ``data:`` payloads of every ``want`` event."""
    out: list[dict[str, Any]] = []
    for raw in sse:
        etype = ""
        payload = ""
        for line in raw.split("\n"):
            if line.startswith("event: "):
                etype = line[7:].strip()
            elif line.startswith("data: "):
                payload = line[6:]
        if etype == want and payload:
            out.append(json.loads(payload))
    return out


_FINDINGS: list[dict[str, Any]] = [
    {
        "severity": "high",
        "category": "exposed-endpoint",
        "title": "Exposed debug endpoint: /debug",
        "description": "d1",
        "recommendation": "r1",
    },
    {
        "severity": "low",
        "category": "information-disclosure",
        "title": "Server version disclosed",
        "description": "d2",
        # no recommendation key: exercises the .get() default on both paths
    },
    {
        "severity": "medium",
        "category": "graphql-exposure",
        "title": "GraphQL introspection enabled",
        "description": "d3",
        "recommendation": "r3",
        # an explicitly non-deterministic row must stay non-deterministic on
        # BOTH paths, not be flattened to the "skill" default by one of them
        "provenance": "llm",
    },
]


@pytest.fixture
def discover_events(monkeypatch):
    """Run ``run_discover`` with all network / disk side effects stubbed out."""
    monkeypatch.setattr(agent_mod, "_ensure_plugins_registered", lambda: None)

    class _Learnings:
        source_routes: list[str] = []
        technologies: list[str] = []
        insights: list[str] = []
        endpoint_behaviors: dict[str, Any] = {}

    monkeypatch.setattr(agent_mod, "load_learnings", lambda _u: _Learnings())
    monkeypatch.setattr(agent_mod, "save_learnings", lambda _u, _l: None)
    monkeypatch.setattr(agent_mod, "format_learnings_context", lambda _l: "")
    monkeypatch.setattr(agent_mod, "load_cached_discovery", lambda _u: None)
    monkeypatch.setattr(agent_mod, "is_cache_fresh", lambda _u, **_k: False)
    monkeypatch.setattr(agent_mod, "save_discovery_cache", lambda _u, _s: None)

    async def _fake_pipeline(_target, **_kwargs):
        return SiteMap(api_endpoints=["/api/a"], urls=["/a"]), []

    monkeypatch.setattr(agent_mod, "_run_discovery_pipeline", _fake_pipeline)
    monkeypatch.setattr(
        agent_mod,
        "analyze_security_exposures",
        lambda _site, _url: [dict(f) for f in _FINDINGS],
    )

    # no source_path and ignore_scan_results: keeps the run off the network
    # entirely (no source analysis, no backend scan-findings fetch).
    return list(
        agent_mod.run_discover(
            "run-0078",
            "",
            {
                "target_url": "http://127.0.0.1:1/",
                "source_path": "",
                "ignore_scan_results": True,
            },
            [],
        )
    )


class TestDiscoverProvenanceParity:
    def test_snapshot_rows_carry_provenance(self, discover_events):
        results = _events(discover_events, "result")
        assert len(results) == 1
        rows = results[0]["findings"]
        assert len(rows) == len(_FINDINGS)
        assert all(r.get("provenance") for r in rows), rows

    def test_delta_agrees_with_the_result_snapshot(self, discover_events):
        deltas = _events(discover_events, "finding")
        rows = _events(discover_events, "result")[0]["findings"]
        assert len(deltas) == len(rows) == len(_FINDINGS)

        delta_prov = [(d["title"], d.get("provenance")) for d in deltas]
        snap_prov = [(r["title"], r.get("provenance")) for r in rows]
        assert delta_prov == snap_prov

    def test_explicit_llm_provenance_is_not_flattened(self, discover_events):
        deltas = _events(discover_events, "finding")
        rows = _events(discover_events, "result")[0]["findings"]
        title = "GraphQL introspection enabled"
        assert [d["provenance"] for d in deltas if d["title"] == title] == ["llm"]
        assert [r["provenance"] for r in rows if r["title"] == title] == ["llm"]
