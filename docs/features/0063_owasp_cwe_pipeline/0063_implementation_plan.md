# OWASP-over-CWE Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the OWASP agent from re-detecting vulnerabilities; the CWE agent detects (the heavy lifting), and the OWASP agent consumes CWE-tagged findings, maps each to OWASP Top 10 categories via edition-versioned data files, and reports categorized results with a coverage manifest that never fails.

**Architecture (revised after audit):** The OWASP Top 10 is, by OWASP's own definition, a grouping over CWE. We make that executable **within a single audit stream** — no new pipeline stages, no DB schema changes:

1. `owasp` is marked **Optional** in the agent registry, so it is removed from the default concurrent scan set (`ScanAgentTypes()`). This alone kills the current duplicate/concurrent-with-CWE problem.
2. When an audit's types include `owasp`, `stream_service` runs the scan agents (CWE among them — auto-injected if absent) to completion **first**, taps every finding whose `category` matches `CWE-<n>`, then launches the OWASP agent as a **deferred phase** in the same stream, passing those findings via the existing `prior_findings` transport.
3. The OWASP agent is a pure mapper: it maps each CWE finding to its OWASP category for the selected edition, re-labels it, and emits a per-category coverage manifest. It never scans and never fails.
4. Editions are JSON data files (2021 default, 2025 available); adding a future edition is one file plus one registry line.

**Tech Stack:** Python 3.12 (agents, pydantic, FastAPI, pytest), Go 1.24 (backend orchestrator, `go test`), JSON data files via `importlib.resources`.

## Global Constraints

- **E2E business-logic tests first, never modified to make code pass** (CLAUDE.md Rules 1 & 2). Write the test, watch it fail, implement.
- **No CWE detection logic may live in `agents/owasp/`** after this feature. Detection is the CWE agent's sole responsibility. Enforced by test (Task 6).
- **The OWASP agent must never fail an audit.** Absent/failed/partial CWE input → clear notice + a full manifest annotated with `cwe_stage_status`, then `agent_end status=completed`. Never raise.
- **Edition extensibility:** a future OWASP edition MUST require only a new data file + one registry line — no engine, agent, or backend change.
- **Mapping data provenance:** every edition category carries `source_url` + `retrieved`, copied from the official OWASP page. Do not invent CWE membership.
- **Single source of truth for OWASP↔CWE:** the shared edition files. The pre-existing 0050 representative-CWE map (`backend/internal/cwe/`) is guarded against divergence by a reconciliation test (Task 13), not duplicated.
- **No secret propagation:** CWE findings' `code_snippet` is NOT carried into OWASP priors (snippets can contain secrets). Priors carry file + line + metadata only.
- Preserve the SSE contract (`agent_start`, `thinking`, `finding`, `progress`, `result`, `agent_end`) and the AgUI translation in `backend/internal/agui/translator.go`.
- Python: type hints on all functions; `ruff` clean; the OWASP mapper is deterministic — no `@function_tool`, no LLM.
- Go: wrap errors `fmt.Errorf("op: %w", err)`; no panics; handlers/services take interfaces.
- Post-edit verification: Python `cd agents/<c> && PYTHONPATH=../shared python -m pytest tests/unit/ -q`; Go `cd backend && go vet ./... && go test ./<pkg>/`.

---

## File Structure

**New — shared mapping (single source of truth):**
- `agents/shared/shared/owasp/__init__.py`
- `agents/shared/shared/owasp/mapping.py` — edition loader + `Edition.map_cwe()` + `parse_cwe_id()`
- `agents/shared/shared/owasp/coverage.py` — coverage manifest builder (with provenance)
- `agents/shared/shared/owasp/editions/owasp_2021.json`, `owasp_2025.json`, `registry.json`

**Modified — shared emitter:**
- `agents/shared/shared/transport/event_emitter.py` — add `extra` param to `result_event`

**Rewritten — OWASP agent (scanner → mapper):**
- `agents/owasp/owasp_agent/agent.py`, `config.py`, `skills/__init__.py`, `skills/SKILLS.md`
- Deleted: the 10 detection skill files + `tests/unit/test_skills.py`, `test_new_skills.py`

**Modified — CWE agent (close measured gaps):**
- `agents/cwe/cwe_agent/skills/resource_check.py` (CWE-799, file-scoped), and any 2025 gaps found in Task 10
- `agents/cwe/cwe_agent/skills/SKILLS.md`

**Modified — Go backend:**
- `pkg/agentregistry/registry.go` — mark `owasp` Optional
- `backend/internal/agui/translator.go` (or new `finding_parse.go` in that pkg) — export `ParseDeltaFindings`
- `backend/internal/handler/stream_handler.go` — reuse the exported parser (DRY)
- `backend/internal/service/stream_service.go` — deferred OWASP phase + CWE-finding tap + cwe auto-inject
- `backend/internal/model/finding.go` — add `LineStart`/`LineEnd` to `PriorFinding` (additive)

**Modified — frontend:**
- `frontend/src/components/results/` — new `OwaspCoverage.tsx`; wire into results page
- `frontend/src/lib/types.ts` — coverage manifest type

**Tests:** listed per task.

---

## Task 1: Edition mapping data files + registry

**Files:**
- Create: `agents/shared/shared/owasp/__init__.py`
- Create: `agents/shared/shared/owasp/editions/{owasp_2021.json,owasp_2025.json,registry.json}`

**Interfaces:**
- Produces: three JSON files consumed by Task 2's loader.

Edition file schema (two categories shown; fill all 10):

```json
{
  "edition": "2021",
  "title": "OWASP Top 10:2021",
  "categories": [
    {
      "id": "A01", "slug": "A01-broken-access-control", "name": "Broken Access Control",
      "source_url": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/",
      "retrieved": "2026-07-07",
      "cwes": [22,23,35,59,200,201,219,264,275,276,284,285,352,359,377,402,425,441,497,538,540,548,552,566,601,639,651,668,706,862,863,913,922,1275]
    },
    {
      "id": "A10", "slug": "A10-ssrf", "name": "Server-Side Request Forgery (SSRF)",
      "source_url": "https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
      "retrieved": "2026-07-07", "cwes": [918]
    }
  ]
}
```

`registry.json`:
```json
{ "default": "2021", "editions": { "2021": "owasp_2021.json", "2025": "owasp_2025.json" } }
```

- [ ] **Step 1: Create `__init__.py`**

```python
"""OWASP Top 10 edition mapping: CWE membership per category, per edition."""
```

- [ ] **Step 2: Author `owasp_2021.json` (all 10 categories)** using these verified 2021 CWE lists (from the official 2021 category pages). Note XXE/CWE-611 lives in **A05 only** in 2021 (merged into Security Misconfiguration); do not place it in A03.

- A01 Broken Access Control: `22,23,35,59,200,201,219,264,275,276,284,285,352,359,377,402,425,441,497,538,540,548,552,566,601,639,651,668,706,862,863,913,922,1275`
- A02 Cryptographic Failures: `261,296,310,319,321,322,323,324,325,326,327,328,329,330,331,335,336,337,338,340,347,523,720,757,759,760,780,818,916`
- A03 Injection: `20,74,75,77,78,79,80,83,87,88,89,90,91,93,94,95,96,97,98,99,100,113,116,138,184,470,471,564,610,643,644,652,917`
- A04 Insecure Design: `73,183,209,213,235,256,257,266,269,280,311,312,313,316,419,430,434,444,451,472,501,522,525,539,579,598,602,642,646,650,653,656,657,799,807,840,841,927,1021,1173`
- A05 Security Misconfiguration: `2,11,13,15,16,260,315,520,526,537,541,547,611,614,756,776,942,1004,1032,1174`
- A06 Vulnerable and Outdated Components: `937,1035,1104`
- A07 Identification and Authentication Failures: `255,259,287,288,290,294,295,297,300,302,304,306,307,346,384,521,613,620,640,798,940,1216`
- A08 Software and Data Integrity Failures: `345,353,426,494,502,565,784,829,830,915`
- A09 Security Logging and Monitoring Failures: `117,223,532,778`
- A10 SSRF: `918`

Each category object needs `id, slug, name, source_url` (its official OWASP page), `retrieved: "2026-07-07"`, `cwes`.

- [ ] **Step 3: Author `owasp_2025.json` (all 10 categories)** from the official 2025 pages (`https://owasp.org/Top10/2025/`). 2025 category set: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions. Copy each category's published CWE list from its 2025 page; set `edition:"2025"`, per-category `source_url`, `retrieved:"2026-07-07"`. **Do not reuse 2021 lists.** A10 (new) centers on CWE-703/754/755/248/390/391.

- [ ] **Step 4: Create `registry.json`** exactly as above.

- [ ] **Step 5: Validate**

```bash
cd agents/shared && python -c "
import json, pathlib
d = pathlib.Path('shared/owasp/editions'); reg = json.loads((d/'registry.json').read_text())
for ed, fn in reg['editions'].items():
    cats = json.loads((d/fn).read_text())['categories']
    assert len(cats) == 10, f'{ed}: {len(cats)} categories'
    for c in cats:
        assert all(isinstance(x, int) for x in c['cwes']), c['id']
        assert c['source_url'].startswith('https://owasp.org'), c['id']
    print(ed, 'OK', sum(len(c['cwes']) for c in cats), 'cwe refs')
"
```
Expected: `2021 OK ... ` and `2025 OK ...`, no assertion errors.

- [ ] **Step 6: Commit**

```bash
git add agents/shared/shared/owasp/
git commit -m "feat(0063): OWASP Top 10 edition CWE-mapping data files (2021 + 2025)"
```

---

## Task 2: Mapping engine

**Files:**
- Create: `agents/shared/shared/owasp/mapping.py`
- Test: `agents/shared/tests/unit/test_owasp_mapping.py`

**Interfaces:**
- Produces: `load_edition(edition_id=None) -> Edition` (None → default; bad id → `UnknownEditionError`); `Edition.map_cwe(cwe_id:int) -> list[Category]` (list because the engine supports multi-category membership); `Category(id,slug,name,cwes:frozenset[int],source_url)`; `available_editions() -> list[str]`; `parse_cwe_id(str) -> int|None`.

- [ ] **Step 1: Write the failing test**

Create `agents/shared/tests/unit/test_owasp_mapping.py`:

```python
import pytest
from shared.owasp.mapping import (
    UnknownEditionError, available_editions, load_edition, parse_cwe_id,
)


def test_default_edition_is_2021():
    ed = load_edition()
    assert ed.edition_id == "2021"
    assert len(ed.categories) == 10


def test_available_editions_lists_both():
    assert set(available_editions()) >= {"2021", "2025"}


def test_parse_cwe_id():
    assert parse_cwe_id("CWE-1321") == 1321
    assert parse_cwe_id("CWE-89") == 89
    assert parse_cwe_id("A03-injection") is None
    assert parse_cwe_id("") is None


def test_map_cwe_to_category_2021():
    assert any(c.id == "A03" for c in load_edition("2021").map_cwe(89))


def test_ssrf_maps_only_to_a10_in_2021():
    assert [c.id for c in load_edition("2021").map_cwe(918)] == ["A10"]


def test_map_cwe_always_returns_a_list():
    # Engine supports multi-category membership; return type is always a list
    # (empty for unmapped). We do NOT assert a specific multi-category CWE
    # here because 2021 membership is near-disjoint and any specific overlap
    # must be verified against the OWASP pages, not assumed.
    ed = load_edition("2021")
    assert ed.map_cwe(89) == [c for c in ed.categories if 89 in c.cwes]
    assert ed.map_cwe(999999) == []


def test_unknown_edition_raises():
    with pytest.raises(UnknownEditionError):
        load_edition("1999")
```

- [ ] **Step 2: Verify it fails**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_owasp_mapping.py -q`
Expected: FAIL `ModuleNotFoundError: shared.owasp.mapping`.

- [ ] **Step 3: Implement `mapping.py`**

```python
"""Load OWASP Top 10 editions and resolve CWE IDs to their categories."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

_CWE_RE = re.compile(r"^CWE-(\d+)$")
_EDITIONS_PKG = "shared.owasp.editions"


class UnknownEditionError(ValueError):
    """Raised when an edition id is not in the registry."""


@dataclass(frozen=True)
class Category:
    id: str
    slug: str
    name: str
    cwes: frozenset[int]
    source_url: str


@dataclass(frozen=True)
class Edition:
    edition_id: str
    title: str
    categories: tuple[Category, ...]

    def map_cwe(self, cwe_id: int) -> list[Category]:
        return [c for c in self.categories if cwe_id in c.cwes]


def parse_cwe_id(category_field: str) -> int | None:
    if not category_field:
        return None
    m = _CWE_RE.match(category_field.strip())
    return int(m.group(1)) if m else None


def _read_json(filename: str) -> dict:
    return json.loads(resources.files(_EDITIONS_PKG).joinpath(filename).read_text("utf-8"))


@lru_cache(maxsize=1)
def _registry() -> dict:
    return _read_json("registry.json")


def available_editions() -> list[str]:
    return sorted(_registry()["editions"].keys())


@lru_cache(maxsize=8)
def load_edition(edition_id: str | None = None) -> Edition:
    reg = _registry()
    eid = edition_id or reg["default"]
    filename = reg["editions"].get(eid)
    if filename is None:
        raise UnknownEditionError(
            f"unknown OWASP edition {eid!r}; available: {available_editions()}"
        )
    doc = _read_json(filename)
    cats = tuple(
        Category(id=c["id"], slug=c["slug"], name=c["name"],
                 cwes=frozenset(c["cwes"]), source_url=c["source_url"])
        for c in doc["categories"]
    )
    return Edition(edition_id=doc["edition"], title=doc["title"], categories=cats)
```

- [ ] **Step 4: Verify it passes**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_owasp_mapping.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add agents/shared/shared/owasp/mapping.py agents/shared/tests/unit/test_owasp_mapping.py
git commit -m "feat(0063): CWE->OWASP-category mapping engine with edition loader"
```

---

## Task 3: Coverage manifest builder (with provenance)

**Files:**
- Create: `agents/shared/shared/owasp/coverage.py`
- Test: `agents/shared/tests/unit/test_owasp_coverage_report.py`

**Interfaces:**
- Produces: `build_manifest(edition, detected_cwes:set[int], cwe_stage_status:str="completed") -> CoverageManifest`; `CoverageManifest.to_dict()`; per-category `CategoryCoverage(id,name,mapped_count,found_cwes,source_url)` with `.found_count`, `.status`. The manifest records `cwe_stage_status` so a partial/failed/absent CWE run is visible in the report (audit finding #5).

- [ ] **Step 1: Write the failing test**

Create `agents/shared/tests/unit/test_owasp_coverage_report.py`:

```python
import json
from shared.owasp.coverage import build_manifest
from shared.owasp.mapping import load_edition


def test_manifest_covers_every_category():
    m = build_manifest(load_edition("2021"), detected_cwes={89, 918})
    assert len(m.categories) == 10
    a03 = next(c for c in m.categories if c.id == "A03")
    assert 89 in a03.found_cwes and a03.status == "found"
    assert next(c for c in m.categories if c.id == "A10").found_cwes == [918]


def test_empty_category_reported_not_dropped():
    m = build_manifest(load_edition("2021"), detected_cwes=set())
    a01 = next(c for c in m.categories if c.id == "A01")
    assert a01.found_count == 0 and a01.status == "clean-or-undetected"
    assert a01.mapped_count == 34


def test_manifest_records_cwe_stage_status():
    m = build_manifest(load_edition("2021"), detected_cwes=set(), cwe_stage_status="failed")
    d = m.to_dict()
    assert d["cwe_stage_status"] == "failed"
    json.dumps(d)  # json-safe
```

- [ ] **Step 2: Verify it fails**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_owasp_coverage_report.py -q`
Expected: FAIL `ModuleNotFoundError`.

- [ ] **Step 3: Implement `coverage.py`**

```python
"""Build a per-category OWASP coverage manifest from detected CWE ids."""

from __future__ import annotations

from dataclasses import dataclass

from shared.owasp.mapping import Edition


@dataclass(frozen=True)
class CategoryCoverage:
    id: str
    name: str
    mapped_count: int
    found_cwes: list[int]
    source_url: str

    @property
    def found_count(self) -> int:
        return len(self.found_cwes)

    @property
    def status(self) -> str:
        return "found" if self.found_cwes else "clean-or-undetected"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "mapped_count": self.mapped_count,
            "found_cwes": [f"CWE-{c}" for c in self.found_cwes],
            "found_count": self.found_count, "status": self.status,
            "source_url": self.source_url,
        }


@dataclass(frozen=True)
class CoverageManifest:
    edition_id: str
    categories: list[CategoryCoverage]
    cwe_stage_status: str  # completed | partial | failed | absent

    def to_dict(self) -> dict:
        return {
            "edition": self.edition_id,
            "cwe_stage_status": self.cwe_stage_status,
            "categories": [c.to_dict() for c in self.categories],
        }


def build_manifest(
    edition: Edition, detected_cwes: set[int], cwe_stage_status: str = "completed",
) -> CoverageManifest:
    cats = [
        CategoryCoverage(id=c.id, name=c.name, mapped_count=len(c.cwes),
                         found_cwes=sorted(detected_cwes & c.cwes), source_url=c.source_url)
        for c in edition.categories
    ]
    return CoverageManifest(edition.edition_id, cats, cwe_stage_status)
```

- [ ] **Step 4: Verify it passes**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_owasp_coverage_report.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add agents/shared/shared/owasp/coverage.py agents/shared/tests/unit/test_owasp_coverage_report.py
git commit -m "feat(0063): OWASP coverage manifest builder with cwe-stage provenance"
```

---

## Task 4: Emitter — first-class `extra` on `result_event`

**Files:**
- Modify: `agents/shared/shared/transport/event_emitter.py`
- Test: `agents/shared/tests/unit/test_event_emitter_extra.py`

**Interfaces:**
- Produces: `result_event(findings, summary, score, extra: dict | None = None) -> str` — merges `extra` into the result payload. Fixes audit finding #13 (mapper no longer reparses its own SSE output).

- [ ] **Step 1: Write the failing test**

Create `agents/shared/tests/unit/test_event_emitter_extra.py`:

```python
import json
from shared.transport.event_emitter import AgUiEventEmitter


def test_result_event_merges_extra():
    e = AgUiEventEmitter("r1")
    s = e.result_event(findings=[], summary="s", score=1.0, extra={"owasp_coverage": {"edition": "2021"}})
    data = json.loads(s.split("data: ", 1)[1])
    assert data["owasp_coverage"]["edition"] == "2021"
    assert data["summary"] == "s"


def test_result_event_without_extra_unchanged():
    e = AgUiEventEmitter("r1")
    data = json.loads(e.result_event(findings=[], summary="s", score=1.0).split("data: ", 1)[1])
    assert "owasp_coverage" not in data
```

- [ ] **Step 2: Verify it fails**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_event_emitter_extra.py -q`
Expected: FAIL (`extra` is not a parameter).

- [ ] **Step 3: Implement** — modify `result_event` in `event_emitter.py`:

```python
    def result_event(
        self,
        findings: list[dict[str, Any]],
        summary: str,
        score: float,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Emit result event with findings and summary."""
        data: dict[str, Any] = {
            "findings": findings,
            "findings_count": len(findings),
            "summary": summary,
            "score": score,
        }
        if extra:
            data.update(extra)
        return self._format("result", data)
```

- [ ] **Step 4: Verify it passes + no regression**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_event_emitter_extra.py tests/unit -k emitter -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agents/shared/shared/transport/event_emitter.py agents/shared/tests/unit/test_event_emitter_extra.py
git commit -m "feat(0063): result_event accepts first-class extra payload"
```

---

## Task 5: OWASP agent rewrite — scanner to mapper

**Files:**
- Rewrite: `agents/owasp/owasp_agent/agent.py`
- Modify: `agents/owasp/owasp_agent/config.py`
- Delete: `agents/owasp/owasp_agent/skills/*.py` except `__init__.py`; rewrite `__init__.py`
- Delete: `agents/owasp/tests/unit/test_skills.py`, `test_new_skills.py`
- Test: `agents/owasp/tests/unit/test_owasp_mapper.py`

**Interfaces:**
- Consumes: `load_edition`, `parse_cwe_id` (Task 2); `build_manifest` (Task 3); `result_event(extra=...)` (Task 4); `compute_score` (`shared.audit_runner`); `AgUiEventEmitter`; `prior_findings: list[dict]` from the `/run` payload (native transport).
- Produces: `run_audit(run_id, source_path, config, prior_findings=None) -> Generator[str,None,None]`. Reads `config["edition"]`, optional `config["categories"]` (ids like `["A01"]`), optional `config["cwe_stage_status"]` (default `"completed"`; `"absent"` when no priors).

- [ ] **Step 1: Write the failing test**

Create `agents/owasp/tests/unit/test_owasp_mapper.py`:

```python
import json
from owasp_agent.agent import run_audit


def _events(gen):
    out = []
    for chunk in gen:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _cwe(cwe, title, path="app.py", line=10):
    return {"category": f"CWE-{cwe}", "title": title, "severity": "critical",
            "file_path": path, "line_start": line, "line_end": line,
            "description": "d", "check_id": f"cwe.x.{cwe}"}


def test_maps_cwe_findings_to_owasp_categories():
    prior = [_cwe(89, "SQL injection"), _cwe(918, "SSRF")]
    findings = [d for t, d in _events(run_audit("r1", "/s", {"edition": "2021"}, prior))
                if t == "finding"]
    cats = {f["category"] for f in findings}
    assert any(c.startswith("A03") for c in cats)
    assert any(c.startswith("A10") for c in cats)
    assert all(f["mapped_from"].startswith("CWE-") for f in findings)


def test_result_carries_coverage_manifest():
    result = [d for t, d in _events(run_audit("r2", "/s", {"edition": "2021"}, [_cwe(89, "x")]))
              if t == "result"][0]
    assert len(result["owasp_coverage"]["categories"]) == 10
    assert result["owasp_coverage"]["cwe_stage_status"] == "completed"


def test_no_prior_findings_completes_without_failure():
    events = _events(run_audit("r3", "/s", {"edition": "2021", "cwe_stage_status": "absent"}, None))
    types = [t for t, _ in events]
    assert "result" in types and types[-1] == "agent_end"
    assert [d for t, d in events if t == "agent_end"][0]["status"] == "completed"
    assert "CWE" in " ".join(d.get("content", "") for t, d in events if t == "thinking")
    assert [d for t, d in events if t == "result"][0]["owasp_coverage"]["cwe_stage_status"] == "absent"


def test_category_filter_restricts_output():
    prior = [_cwe(89, "SQLi"), _cwe(918, "SSRF")]
    findings = [d for t, d in _events(run_audit("r4", "/s", {"edition": "2021", "categories": ["A10"]}, prior))
                if t == "finding"]
    assert findings and all(f["category"].startswith("A10") for f in findings)


def test_no_code_snippet_leaks_into_owasp_findings():
    # Priors from the backend never include snippets; even if one sneaks in,
    # the mapper must not echo it (defense-in-depth, audit finding #6).
    p = _cwe(89, "SQLi"); p["code_snippet"] = "SECRET_KEY = 'sk-live-xyz'"
    findings = [d for t, d in _events(run_audit("r5", "/s", {"edition": "2021"}, [p]))
                if t == "finding"]
    assert all("code_snippet" not in f or f["code_snippet"] == "" for f in findings)
```

- [ ] **Step 2: Verify it fails**

Run: `cd agents/owasp && PYTHONPATH=../shared:. python -m pytest tests/unit/test_owasp_mapper.py -q`
Expected: FAIL (old `agent.py` imports `run_combined_audit`; new behavior absent).

- [ ] **Step 3: Rewrite `agent.py`**

```python
"""OWASP Top 10 agent: maps CWE findings onto OWASP categories.

Performs NO detection. The CWE agent detects and tags findings with
`category: "CWE-NNN"`; this agent consumes those (via prior_findings),
maps each to its OWASP Top 10 category for the selected edition,
re-labels it, and emits a per-category coverage manifest. Never fails.
"""

from collections.abc import Generator
from typing import Any

from shared.audit_runner import compute_score
from shared.owasp.coverage import build_manifest
from shared.owasp.mapping import Edition, load_edition, parse_cwe_id
from shared.transport.event_emitter import AgUiEventEmitter

_PREREQ_NOTICE = (
    "OWASP agent requires the CWE agent to run first. No CWE findings were "
    "provided, so nothing can be categorized — reporting zero coverage."
)
# Fields carried from a CWE finding into an OWASP finding. code_snippet is
# deliberately EXCLUDED (snippets may contain secrets — audit finding #6).
_CARRY = ("severity", "description", "file_path", "line_start", "line_end", "recommendation")


def _manifest_summary(m: dict) -> str:
    lines = [f"OWASP Top 10:{m['edition']} coverage (CWE stage: {m['cwe_stage_status']}):"]
    for c in m["categories"]:
        lines.append(f"  {c['id']} {c['name']}: {c['found_count']}/{c['mapped_count']} found ({c['status']})")
    return "\n".join(lines)


def _relabel(finding: dict, cat, cwe_id: int, run_id: str, idx: int) -> dict:
    out = {k: finding[k] for k in _CARRY if k in finding}
    out["id"] = f"{run_id}-owasp-{idx}"
    out["category"] = cat.slug
    out["owasp_category_id"] = cat.id
    out["owasp_category_name"] = cat.name
    out["mapped_from"] = f"CWE-{cwe_id}"
    out["check_id"] = f"owasp.{cat.id}.cwe-{cwe_id}"
    out["references"] = list(dict.fromkeys([*finding.get("references", []), cat.source_url]))
    title = finding.get("title", "")
    out["title"] = title if title.startswith(f"[{cat.id}]") else f"[{cat.id}] {title}".strip()
    return out


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    edition: Edition = load_edition(config.get("edition"))
    selected = set(config.get("categories") or [])
    priors = prior_findings or []
    cwe_status = config.get("cwe_stage_status") or ("absent" if not priors else "completed")

    yield emitter.text_message(
        f"Categorizing {len(priors)} CWE finding(s) against OWASP Top 10:{edition.edition_id}."
    )
    if not priors:
        yield emitter.text_message(_PREREQ_NOTICE)

    detected: set[int] = set()
    emitted: list[dict] = []
    idx = 0
    for f in priors:
        cwe_id = parse_cwe_id(str(f.get("category", "")))
        if cwe_id is None:
            continue
        detected.add(cwe_id)
        for cat in edition.map_cwe(cwe_id):
            if selected and cat.id not in selected:
                continue
            relabeled = _relabel(f, cat, cwe_id, run_id, idx)
            idx += 1
            emitted.append(relabeled)
            yield emitter.finding_event(**relabeled)

    manifest = build_manifest(edition, detected, cwe_stage_status=cwe_status).to_dict()
    yield emitter.text_message(_manifest_summary(manifest))
    files = {f.get("file_path", "") for f in priors}
    yield emitter.progress_event(len(files), len(files), len(emitted))

    found = sum(1 for c in manifest["categories"] if c["found_count"] > 0)
    summary = f"Mapped {len(emitted)} finding(s) into {found}/10 OWASP Top 10:{edition.edition_id} categories."
    # Reuse the shared scoring convention so the UI treats this agent's score
    # consistently with every other agent (audit finding #14).
    score = compute_score(emitted, max(len(priors), len(emitted)))
    yield emitter.result_event(findings=emitted, summary=summary, score=score,
                               extra={"owasp_coverage": manifest})
    yield emitter.run_finished(status="completed")
```

> `finding_event(**relabeled)` works because `finding_event` accepts `**extra`; the relabeled dict's keys (`severity, category, title, description, file_path, line_start, line_end, recommendation` + owasp extras) all land in the payload. No snippet key is present.

- [ ] **Step 4: Update `config.py`**

```python
"""OWASP agent configuration (mapping mode, feature 0063)."""

CATEGORY_IDS: list[str] = [f"A{n:02d}" for n in range(1, 11)]


def _default_edition() -> str:
    # Lazy, fault-tolerant: never let a bad data file break agent import
    # (audit finding #12). Falls back to "2021" if the registry is unreadable.
    try:
        from shared.owasp.mapping import load_edition
        return load_edition().edition_id
    except Exception:
        return "2021"


def _editions() -> list[str]:
    try:
        from shared.owasp.mapping import available_editions
        return available_editions()
    except Exception:
        return ["2021"]


CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "edition": {"type": "string", "enum": _editions(),
                    "description": "OWASP Top 10 edition to map against", "default": _default_edition()},
        "categories": {"type": "array", "items": {"type": "string", "enum": CATEGORY_IDS},
                       "description": "OWASP category ids to include (empty = all)", "default": []},
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "OWASP Top 10 Categorizer",
    "type": "owasp",
    "description": ("Maps CWE findings (from the CWE agent, a prerequisite) onto OWASP "
                    "Top 10 categories for a selected edition. Performs no detection."),
    "requires": ["cwe"],
    "config_schema": CONFIG_SCHEMA,
    "skills": [],
}
```

- [ ] **Step 5: Delete detection skills + obsolete tests; empty the skills package**

```bash
cd agents/owasp/owasp_agent/skills && git rm injection_check.py auth_check.py crypto_check.py \
  access_control.py security_misconfig.py insecure_design.py vulnerable_components.py \
  data_integrity.py logging_check.py ssrf_check.py
cd /home/user/src/vulture/agents/owasp && git rm tests/unit/test_skills.py tests/unit/test_new_skills.py
```

Rewrite `agents/owasp/owasp_agent/skills/__init__.py`:

```python
"""OWASP agent defines no detection skills (feature 0063).

Detection is delegated to the CWE agent; this agent maps CWE findings onto
OWASP Top 10 categories. See owasp_agent/agent.py.
"""

SKILL_MAP: dict = {}
SKILL_TOOLS: list = []
```

- [ ] **Step 6: Verify mapper tests pass**

Run: `cd agents/owasp && PYTHONPATH=../shared:. python -m pytest tests/unit/test_owasp_mapper.py -q`
Expected: PASS (5 passed).

- [ ] **Step 7: Commit**

```bash
git add -A agents/owasp/
git commit -m "feat(0063): rewrite OWASP agent as CWE->category mapper; drop detection skills"
```

---

## Task 6: OWASP agent guardrail + E2E over the native transport

**Files:**
- Create: `agents/owasp/tests/unit/test_no_detection.py`
- Rewrite: `agents/owasp/tests/e2e/test_owasp_audit.py`

**Interfaces:**
- Consumes: FastAPI `/run` from `owasp_agent.main` (wired via `shared.transport.sse_app`, which forwards `req.prior_findings` — the same transport the backend uses in Task 9).

- [ ] **Step 1: Write the guardrail test (asserts no detection, via imports not substring grep — audit finding #16)**

Create `agents/owasp/tests/unit/test_no_detection.py`:

```python
import importlib
import pkgutil


def test_skills_package_exposes_no_detection():
    from owasp_agent import skills
    assert skills.SKILL_MAP == {}
    assert skills.SKILL_TOOLS == []


def test_no_detection_skill_modules_remain():
    from owasp_agent import skills
    names = [m.name for m in pkgutil.iter_modules(skills.__path__)]
    assert names == [], f"unexpected detection skill modules present: {names}"


def test_agent_does_not_import_combined_audit():
    import owasp_agent.agent as agent
    # run_combined_audit must not be a bound symbol in the mapper module.
    assert not hasattr(agent, "run_combined_audit")
    assert not hasattr(agent, "SKILL_MAP")
```

- [ ] **Step 2: Write the E2E test (native prior_findings body — the real backend path)**

Replace `agents/owasp/tests/e2e/test_owasp_audit.py`:

```python
"""E2E: OWASP agent maps a CWE payload via the real /run SSE endpoint.

The backend delivers CWE findings through the `prior_findings` payload
field (Task 9). This test uses that exact path.
"""

import json
from fastapi.testclient import TestClient
from owasp_agent.main import app

client = TestClient(app)


def _post(prior, config=None):
    return client.post("/run", json={
        "run_id": "e2e-owasp-1", "source_path": "/tmp/x",
        "config": config or {"edition": "2021"}, "prior_findings": prior,
    })


def test_run_emits_findings_and_coverage():
    prior = [
        {"category": "CWE-89", "title": "SQL injection", "severity": "critical",
         "file_path": "app.py", "line_start": 3, "line_end": 3, "description": "x", "check_id": "cwe.injection.sql"},
        {"category": "CWE-918", "title": "SSRF", "severity": "high",
         "file_path": "net.py", "line_start": 7, "line_end": 7, "description": "y", "check_id": "cwe.ssrf"},
    ]
    resp = _post(prior)
    assert resp.status_code == 200
    text = resp.text
    assert "event: finding" in text and "event: result" in text and "event: agent_end" in text
    block = [b for b in text.split("\n\n") if "event: result" in b][0]
    assert len(json.loads(block.split("data: ", 1)[1])["owasp_coverage"]["categories"]) == 10


def test_run_without_prior_findings_still_completes():
    resp = _post([])
    assert resp.status_code == 200
    assert "event: agent_end" in resp.text and "CWE" in resp.text
```

- [ ] **Step 3: Verify + fix wiring if needed**

Run: `cd agents/owasp && PYTHONPATH=../shared:. python -m pytest tests/ -q`
Expected: PASS. If `main.py` does not forward `prior_findings` to `run_audit`, fix `main.py` (do not change tests) — `sse_app.py` already passes `req.prior_findings`, so the default wiring should work.

- [ ] **Step 4: Commit**

```bash
git add agents/owasp/tests/
git commit -m "test(0063): OWASP no-detection guardrail + E2E over native prior_findings"
```

---

## Task 7: Registry — make `owasp` Optional (remove from concurrent scan set)

**Files:**
- Modify: `pkg/agentregistry/registry.go`
- Test: `backend/pkg/agentregistry/registry_test.go` (or existing test file)

**Interfaces:**
- Produces: `ScanAgentTypes()` no longer includes `owasp`; a default scan runs CWE (and others) but not OWASP. This removes the concurrent OWASP-vs-CWE duplication (audit finding #1). OWASP now runs only when explicitly requested, sequenced after scan (Task 9).

- [ ] **Step 1: Write the failing test**

Add to the agentregistry test file:

```go
func TestScanAgentTypes_ExcludesOwasp(t *testing.T) {
	for _, ty := range ScanAgentTypes() {
		if ty == "owasp" {
			t.Fatal("owasp must be Optional and excluded from the default scan set")
		}
	}
}

func TestScanAgentTypes_IncludesCwe(t *testing.T) {
	found := false
	for _, ty := range ScanAgentTypes() {
		if ty == "cwe" {
			found = true
		}
	}
	if !found {
		t.Fatal("cwe must remain in the default scan set (it is OWASP's prerequisite)")
	}
}
```

- [ ] **Step 2: Verify it fails**

Run: `cd backend && go test ./pkg/agentregistry/ -run TestScanAgentTypes_ExcludesOwasp`
Expected: FAIL (owasp currently in the set).

- [ ] **Step 3: Mark owasp Optional** — in `pkg/agentregistry/registry.go`, add `Optional: true` to the owasp entry:

```go
	{Type: "owasp", Name: "OWASP", DefaultPort: "28002", DirName: "owasp", Module: "owasp_agent.main:app", INIKey: "agent_owasp", Optional: true},
```

- [ ] **Step 4: Verify + full registry tests**

Run: `cd backend && go test ./pkg/agentregistry/`
Expected: PASS. (If a golden test enumerates the default set, update that golden — it encodes the intended set, not a business contract; adjust to match the new intent.)

- [ ] **Step 5: Commit**

```bash
git add backend/pkg/agentregistry/
git commit -m "feat(0063): mark owasp Optional so it no longer runs concurrently with cwe"
```

---

## Task 8: Extract a reusable delta-finding parser (DRY)

**Files:**
- Create: `backend/internal/agui/finding_parse.go`
- Modify: `backend/internal/handler/stream_handler.go` (use the exported parser)
- Test: `backend/internal/agui/finding_parse_test.go`

**Interfaces:**
- Produces: `func ParseDeltaFindings(delta json.RawMessage, auditID, agentType string) []model.Finding` — parses `{"op":"add","path":"/findings/-","value":{...}}` patches into `model.Finding`. Extracted from the existing private `extractDeltaFindings` in `stream_handler.go:864` so both the handler and the new stream-service tap (Task 9) share one implementation.

- [ ] **Step 1: Write the failing test**

Create `backend/internal/agui/finding_parse_test.go`:

```go
package agui

import (
	"encoding/json"
	"testing"
)

func TestParseDeltaFindings_ExtractsCategoryAndLines(t *testing.T) {
	delta := json.RawMessage(`[{"op":"add","path":"/findings/-","value":{"category":"CWE-89","title":"SQLi","severity":"critical","file_path":"a.py","line_start":3,"line_end":3}}]`)
	got := ParseDeltaFindings(delta, "aud1", "cwe")
	if len(got) != 1 || got[0].Category != "CWE-89" || got[0].LineStart != 3 {
		t.Fatalf("bad parse: %+v", got)
	}
}
```

- [ ] **Step 2: Verify it fails**

Run: `cd backend && go test ./internal/agui/ -run TestParseDeltaFindings`
Expected: FAIL (`ParseDeltaFindings` undefined).

- [ ] **Step 3: Implement** — move the body of `extractDeltaFindings` (stream_handler.go:864) into `internal/agui/finding_parse.go` as exported `ParseDeltaFindings` returning `[]model.Finding`. Then in `stream_handler.go`, replace the private function with a thin call to `agui.ParseDeltaFindings(...)` (preserve its append-into-pointer signature by wrapping). Keep behavior identical.

- [ ] **Step 4: Verify + handler tests unchanged**

Run: `cd backend && go vet ./internal/agui/ ./internal/handler/ && go test ./internal/agui/ ./internal/handler/`
Expected: PASS (existing handler finding tests still green).

- [ ] **Step 5: Commit**

```bash
git add backend/internal/agui/ backend/internal/handler/stream_handler.go
git commit -m "refactor(0063): extract agui.ParseDeltaFindings for reuse by handler + stream svc"
```

---

## Task 9: Backend — deferred OWASP phase within the audit stream

**Files:**
- Modify: `backend/internal/model/finding.go` (add `LineStart`/`LineEnd` to `PriorFinding`)
- Modify: `backend/internal/service/stream_service.go`
- Test: `backend/internal/service/stream_service_owasp_test.go`

**Interfaces:**
- Consumes: `agui.ParseDeltaFindings` (Task 8); existing `launch`/`RunAgentWithContext` prior_findings transport; `agents map[string]config.AgentConfig`.
- Produces: `StreamWithContext` behavior — when `audit.Types` contains `owasp`: (1) split it out of the concurrent scan set; (2) if `cwe` is not requested but is configured, add it (prerequisite enforcement — audit finding #18); (3) run the scan agents, forwarding all events while tapping findings whose `category` matches `^CWE-\d+$` into a thread-safe collector; (4) after scan completes, launch the OWASP agent with those findings as `prior_findings` and `cwe_stage_status` in its config; (5) OWASP is launched even when zero CWE findings/failed CWE — it self-reports (never fails). No new audit, no DB schema change.

**Design notes:**
- The tap parses each `EventStateDelta` whose delta is a `/findings/-` add and keeps those with a `CWE-\d+` category. Filtering by category (not agent name) means any CWE-tagged finding maps — robust and future-proof.
- `cwe_stage_status`: `"completed"` normally; `"failed"` if the CWE agent's launch returned an unavailable/error event; `"absent"` if CWE was not in the set and not configured. Passed into OWASP's per-agent config JSON.
- Snippets are never placed in `PriorFinding` (no snippet field exists there — audit finding #6 is satisfied by construction). `LineStart`/`LineEnd` are added so OWASP findings keep line locations.

- [ ] **Step 1: Add line numbers to `PriorFinding`**

In `backend/internal/model/finding.go`, add to the `PriorFinding` struct:

```go
	LineStart int `json:"line_start,omitempty"`
	LineEnd   int `json:"line_end,omitempty"`
```

- [ ] **Step 2: Write the failing test**

Create `backend/internal/service/stream_service_owasp_test.go`. Use a fake `AgentProxyService` that, for `agentType=="cwe"`, emits a finding StateDelta with category `CWE-89`, and records the `priorFindings` it receives for `agentType=="owasp"`.

```go
package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

type fakeProxy struct {
	mu          sync.Mutex
	owaspPriors []model.PriorFinding
}

func (f *fakeProxy) RunAgent(ctx context.Context, url, at, rid, sp string, cfg json.RawMessage, ch chan<- *model.AgUIEvent) error {
	return f.RunAgentWithContext(ctx, url, at, rid, sp, cfg, nil, ch)
}

func (f *fakeProxy) RunAgentWithContext(ctx context.Context, url, at, rid, sp string, cfg json.RawMessage, prior []model.PriorFinding, ch chan<- *model.AgUIEvent) error {
	if at == "cwe" {
		val := `{"id":"f1","category":"CWE-89","title":"SQLi","severity":"critical","file_path":"a.py","line_start":3,"line_end":3}`
		patch, _ := json.Marshal([]map[string]interface{}{{"op": "add", "path": "/findings/-", "value": json.RawMessage(val)}})
		ch <- &model.AgUIEvent{Type: model.EventStateDelta, Delta: patch, AgentType: "cwe"}
	}
	if at == "owasp" {
		f.mu.Lock()
		f.owaspPriors = append([]model.PriorFinding(nil), prior...)
		f.mu.Unlock()
	}
	return nil
}

func TestStream_OwaspReceivesCweFindingsAsPriors(t *testing.T) {
	fp := &fakeProxy{}
	svc := NewStreamService(fp)
	audit := &model.Audit{ID: "a1", Types: []string{"cwe", "owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{
		"cwe":   {URL: "http://cwe"},
		"owasp": {URL: "http://owasp"},
	}
	ch := make(chan *model.AgUIEvent, 64)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, ch)
	for range ch {
	}
	if len(fp.owaspPriors) != 1 || fp.owaspPriors[0].Category != "CWE-89" || fp.owaspPriors[0].LineStart != 3 {
		t.Fatalf("owasp did not receive CWE-89 prior with line: %+v", fp.owaspPriors)
	}
}

func TestStream_OwaspAutoInjectsCwePrereq(t *testing.T) {
	fp := &fakeProxy{}
	svc := NewStreamService(fp)
	// owasp requested WITHOUT cwe; cwe is configured -> must be added + run first.
	audit := &model.Audit{ID: "a2", Types: []string{"owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"cwe": {URL: "http://cwe"}, "owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 64)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, ch)
	for range ch {
	}
	if len(fp.owaspPriors) != 1 {
		t.Fatalf("expected cwe auto-injected so owasp gets 1 prior, got %d", len(fp.owaspPriors))
	}
}
```

- [ ] **Step 3: Verify it fails**

Run: `cd backend && go test ./internal/service/ -run TestStream_Owasp`
Expected: FAIL (OWASP runs concurrently, receives no priors).

- [ ] **Step 4: Implement the deferred phase in `stream_service.go`**

Restructure `StreamWithContext` to split scan vs. mapping and sequence them. Add helpers; keep the existing `dispatchViaRouter`/`dispatchLegacy` for the scan phase but route their output through a tap. Illustrative core:

```go
const owaspType = "owasp"

func (s *streamService) StreamWithContext(ctx context.Context, audit *model.Audit, sourcePath string,
	agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	defer close(eventCh)

	eventCh <- &model.AgUIEvent{Type: model.EventRunStarted, RunID: audit.ID, ThreadID: "t-" + audit.ID}

	scanTypes, wantOwasp := splitOwasp(audit.Types)
	if wantOwasp {
		scanTypes = ensureCwe(scanTypes, agents) // prerequisite enforcement
	}

	// Phase 1: scan agents, tapping CWE-category findings.
	tap := &cweTap{}
	scanAudit := shallowCopyAudit(audit, scanTypes)
	scanCh := make(chan *model.AgUIEvent, 64)
	go func() {
		if s.router != nil {
			s.dispatchViaRouter(ctx, scanAudit, sourcePath, agents, priorByAgent, scanCh)
		} else {
			s.dispatchLegacy(ctx, scanAudit, sourcePath, agents, priorByAgent, scanCh)
		}
		close(scanCh)
	}()
	for ev := range scanCh {
		tap.observe(ev)      // records CWE-\d+ findings + notes cwe failure
		eventCh <- ev        // forward unchanged (RunStarted/Finished suppressed by dispatch* — see note)
	}

	// Phase 2: deferred OWASP mapping.
	if wantOwasp {
		s.runOwaspMapping(ctx, audit, sourcePath, agents, tap, eventCh)
	}

	eventCh <- &model.AgUIEvent{Type: model.EventRunFinished, RunID: audit.ID}
}
```

Supporting pieces to implement in the same file:

```go
func splitOwasp(types []string) (scan []string, wantOwasp bool) {
	for _, t := range types {
		if t == owaspType {
			wantOwasp = true
			continue
		}
		scan = append(scan, t)
	}
	return scan, wantOwasp
}

func ensureCwe(scan []string, agents map[string]config.AgentConfig) []string {
	for _, t := range scan {
		if t == "cwe" {
			return scan
		}
	}
	if _, ok := agents["cwe"]; ok {
		return append(scan, "cwe")
	}
	return scan // cwe not configured; OWASP will report cwe_stage_status="absent"
}

type cweTap struct {
	mu       sync.Mutex
	findings []model.Finding
	cweFailed bool
}

func (t *cweTap) observe(ev *model.AgUIEvent) {
	if ev == nil {
		return
	}
	if ev.Type == model.EventStateDelta && len(ev.Delta) > 0 {
		for _, f := range agui.ParseDeltaFindings(ev.Delta, "", ev.AgentType) {
			if isCWECategory(f.Category) {
				t.mu.Lock()
				t.findings = append(t.findings, f)
				t.mu.Unlock()
			}
		}
	}
	// A "<agent> tier not active" / RunError for cwe marks the stage failed.
	if ev.AgentType == "cwe" && (ev.Type == model.EventRunError) {
		t.mu.Lock(); t.cweFailed = true; t.mu.Unlock()
	}
}

var cweCatRe = regexp.MustCompile(`^CWE-\d+$`)
func isCWECategory(c string) bool { return cweCatRe.MatchString(c) }
```

`runOwaspMapping` builds priors + status and launches OWASP through the existing proxy:

```go
func (s *streamService) runOwaspMapping(ctx context.Context, audit *model.Audit, sourcePath string,
	agents map[string]config.AgentConfig, tap *cweTap, eventCh chan<- *model.AgUIEvent) {
	cfg, ok := agents[owaspType]
	if !ok || cfg.URL == "" {
		eventCh <- agentUnavailableEvent(owaspType)
		return
	}
	tap.mu.Lock()
	priors := findingsToPriors(tap.findings)
	status := cweStageStatus(tap, agents)
	tap.mu.Unlock()

	owaspCfg := extractAgentConfig(parseAuditConfigMap(audit.Config), owaspType)
	owaspCfg = withCweStatus(owaspCfg, status) // merge {"cwe_stage_status": status}

	var wg sync.WaitGroup
	s.launch(ctx, &wg, cfg.URL, owaspType, audit.ID, sourcePath, owaspCfg, priors, eventCh)
	wg.Wait()
}

func findingsToPriors(fs []model.Finding) []model.PriorFinding {
	out := make([]model.PriorFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, model.PriorFinding{
			Title: f.Title, Severity: string(f.Severity), Category: f.Category,
			Description: f.Description, FilePath: f.FilePath,
			LineStart: f.LineStart, LineEnd: f.LineEnd, CheckID: f.CheckID,
			// NOTE: CodeSnippet intentionally omitted (secrets — audit finding #6).
		})
	}
	return out
}

func cweStageStatus(tap *cweTap, agents map[string]config.AgentConfig) string {
	if tap.cweFailed {
		return "failed"
	}
	if len(tap.findings) == 0 {
		if _, ok := agents["cwe"]; !ok {
			return "absent"
		}
	}
	return "completed"
}
```

Implement `shallowCopyAudit` (same audit with overridden `Types`), `withCweStatus` (JSON-merge one key), and add the `regexp`/`agui` imports. **Note on RunStarted/RunFinished:** the current `dispatch*` methods do not emit those (they are emitted by `StreamWithContext`), so forwarding scan events verbatim is safe — verify no double emit when wiring.

- [ ] **Step 5: Verify the OWASP stream tests pass**

Run: `cd backend && go test ./internal/service/ -run TestStream_Owasp`
Expected: PASS (2 passed).

- [ ] **Step 6: Full service + vet**

Run: `cd backend && go vet ./... && go test ./internal/service/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/internal/model/finding.go backend/internal/service/stream_service.go backend/internal/service/stream_service_owasp_test.go
git commit -m "feat(0063): deferred OWASP mapping phase; CWE-finding tap; cwe prereq auto-inject"
```

---

## Task 10: Measure 2025 coverage, then close only real gaps

**Files:**
- Create: `agents/cwe/tests/unit/test_owasp_coverage_floor.py` (derived, not hardcoded — audit finding #10)

**Interfaces:**
- Produces: a parametrized floor test (both editions) that derives the CWE agent's detectable set **by scanning its own skill files** and asserts every OWASP category has ≥1 detectable CWE. This both measures the 2025 baseline (audit finding #9) and permanently guards it in CI.

- [ ] **Step 1: Write the floor test (it doubles as the measurement)**

Create `agents/cwe/tests/unit/test_owasp_coverage_floor.py`:

```python
import pathlib
import re

import pytest

from shared.owasp.mapping import available_editions, load_edition

_SKILLS_DIR = pathlib.Path(__file__).resolve().parents[2] / "cwe_agent" / "skills"
_CWE_RE = re.compile(r"CWE-(\d+)")


def _detected_cwes() -> set[int]:
    """Derive the detectable set from the CWE agent's skill sources.

    No hardcoded list -> cannot drift out of sync with the skills.
    """
    ids: set[int] = set()
    for py in _SKILLS_DIR.rglob("*.py"):
        for m in _CWE_RE.finditer(py.read_text("utf-8")):
            ids.add(int(m.group(1)))
    return ids


@pytest.mark.parametrize("edition_id", available_editions())
def test_every_category_has_a_detectable_cwe(edition_id):
    detected = _detected_cwes()
    ed = load_edition(edition_id)
    blind = [f"{c.id} {c.name}" for c in ed.categories if not (c.cwes & detected)]
    assert not blind, f"{edition_id}: no detectable CWE for {blind}"
```

- [ ] **Step 2: Run it — this reports the real gaps**

Run: `cd agents/cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/test_owasp_coverage_floor.py -q`
Record which categories (if any) fail for 2021 and 2025. Only those categories need new detectors in Tasks 11–12. Do NOT add detectors for categories that already pass. (Baseline measured during planning: all 2021 categories already pass; 2025 must be measured here because its category structure differs.)

- [ ] **Step 3: Commit the guard**

```bash
git add agents/cwe/tests/unit/test_owasp_coverage_floor.py
git commit -m "test(0063): CI floor — every OWASP category (2021+2025) has a detectable CWE"
```

---

## Task 11: CWE agent — CWE-799 (file-scoped) for OWASP A04

**Files:**
- Modify: `agents/cwe/cwe_agent/skills/resource_check.py`
- Modify: `agents/cwe/cwe_agent/skills/SKILLS.md`
- Test: `agents/cwe/tests/unit/test_resource_rate_limit.py`

**Interfaces:**
- Produces: `resource_check` emits `category: "CWE-799"` for auth endpoints lacking rate limiting. This is the one old-OWASP capability with no CWE-agent equivalent; porting it keeps A04 coverage after the OWASP agent stops detecting. Suppression is **file-scoped** (a limiter in the same file), not whole-project — fixing the FP-prone heuristic criticized in the audit (finding #15).

- [ ] **Step 1: Write the failing test**

Create `agents/cwe/tests/unit/test_resource_rate_limit.py`:

```python
from cwe_agent.skills.resource_check import check_resource_management


def test_flags_unthrottled_auth_endpoint(tmp_path):
    (tmp_path / "auth.py").write_text("def login(request):\n    return authenticate(request)\n")
    cwes = {f["category"] for f in check_resource_management(str(tmp_path))["findings"]}
    assert "CWE-799" in cwes


def test_no_799_when_same_file_rate_limited(tmp_path):
    (tmp_path / "auth.py").write_text(
        "@rate_limit('5/min')\ndef login(request):\n    return authenticate(request)\n"
    )
    cwes = {f["category"] for f in check_resource_management(str(tmp_path))["findings"]}
    assert "CWE-799" not in cwes


def test_unrelated_file_limiter_does_not_suppress(tmp_path):
    # File-scoped: a limiter in another file must NOT suppress this endpoint.
    (tmp_path / "other.py").write_text("limiter = RateLimiter()\n")
    (tmp_path / "auth.py").write_text("def login(request):\n    return authenticate(request)\n")
    cwes = {f["category"] for f in check_resource_management(str(tmp_path))["findings"]}
    assert "CWE-799" in cwes
```

- [ ] **Step 2: Verify it fails**

Run: `cd agents/cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/test_resource_rate_limit.py -q`
Expected: FAIL.

- [ ] **Step 3: Implement (file-scoped)** — read `resource_check.py` first to reuse its scanner helpers/finding shape, then add:

```python
import re

_AUTH_FN_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?:login|signin|signup|register|reset_password|forgot_password|authenticate)\b")
_RATE_LIMIT_RE = re.compile(r"rate_?limit|throttle|RateLimiter|slowapi|Limiter\(")


def _check_rate_limiting(source_path, findings):
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        content = read_file_safe(file_path)
        if content is None:
            continue
        if _RATE_LIMIT_RE.search(content):   # file-scoped suppression
            continue
        for i, line in enumerate(content.splitlines(), start=1):
            if _AUTH_FN_RE.match(line):
                findings.append({
                    "severity": "medium", "check_id": "cwe.resource.rate_limit",
                    "category": "CWE-799",
                    "title": "Improper control of interaction frequency (missing rate limiting)",
                    "description": f"Auth endpoint at line {i} with no rate limiting in this file",
                    "file_path": str(file_path), "line_start": i, "line_end": i,
                    "recommendation": "Apply rate limiting/throttling to authentication endpoints",
                })
```

Call `_check_rate_limiting(source_path, findings)` inside `check_resource_management`. Match the module's existing scanner imports.

- [ ] **Step 4: Verify passes + full CWE unit suite**

Run: `cd agents/cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/ -q`
Expected: PASS.

- [ ] **Step 5: Document + commit**

Add a CWE-799 row under `resource_check` in `SKILLS.md`.

```bash
git add agents/cwe/
git commit -m "feat(0063): CWE agent detects CWE-799 (missing rate limiting), file-scoped"
```

---

## Task 12: CWE agent — close measured 2025 gaps (only if Task 10 flagged any)

**Files:** the CWE skill(s) whose category the floor test flagged blind for 2025, + `SKILLS.md`
**Test:** `agents/cwe/tests/unit/test_2025_gaps.py`

**Interfaces:**
- Produces: detectors for any 2025 category the Task 10 floor test reported blind. Likely candidates (verify against Task 10 output before implementing):
  - **A10:2025 Mishandling of Exceptional Conditions** — the agent already emits CWE-248/390/754/755; if the 2025 A10 list includes any of these, **no work needed**. If it needs CWE-703, add an empty/swallowed-catch detector to `error_handling_check.py`.
  - **A03:2025 Software Supply Chain Failures** — the agent already emits CWE-494/1104/829; if the 2025 A03 list includes any, **no work needed**. If it needs CWE-1357, add a VCS/URL-dependency detector to `dependency_check.py`.

- [ ] **Step 1: If Task 10 shows all 2025 categories pass, skip this task** and record "no 2025 gaps" in the status doc. Otherwise continue.

- [ ] **Step 2: Write a failing test for each flagged gap** (example for CWE-703):

```python
def test_error_handling_flags_swallowed_exception(tmp_path):
    from cwe_agent.skills.error_handling_check import check_error_handling
    (tmp_path / "svc.py").write_text("def f():\n    try:\n        risky()\n    except Exception:\n        pass\n")
    cwes = {f["category"] for f in check_error_handling(str(tmp_path))["findings"]}
    assert "CWE-703" in cwes or "CWE-755" in cwes
```

- [ ] **Step 3: Verify fails, implement in the relevant skill (match its style), verify passes.**

Run: `cd agents/cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/test_2025_gaps.py -q` then the floor test again — 2025 must now pass.

- [ ] **Step 4: Document + commit**

```bash
git add agents/cwe/
git commit -m "feat(0063): close measured OWASP-2025 CWE-coverage gaps"
```

---

## Task 13: Guard the 0050 map against the shared editions (DRY / divergence)

**Files:**
- Create: `agents/shared/tests/unit/test_0050_reconciliation.py`

**Interfaces:**
- Produces: a test asserting each representative CWE in the backend 0050 map (`backend/internal/cwe/data/category_to_cwe.json`) is a genuine member of the corresponding shared-edition category — so the two OWASP↔CWE artifacts cannot silently diverge (audit finding #11).

- [ ] **Step 1: Write the test**

Create `agents/shared/tests/unit/test_0050_reconciliation.py`:

```python
import json
import pathlib

import pytest

from shared.owasp.mapping import load_edition, parse_cwe_id

_MAP = pathlib.Path(__file__).resolve().parents[3] / "backend/internal/cwe/data/category_to_cwe.json"
_OWASP_PREFIX = {  # 0050 slug -> shared edition category id
    "A01-access-control": "A01", "A02-crypto-failure": "A02", "A03-injection": "A03",
    "A04-insecure-design": "A04", "A05-security-misconfig": "A05",
    "A06-vulnerable-components": "A06", "A07-auth-failure": "A07",
    "A08-data-integrity": "A08", "A09-logging-failure": "A09", "A10-ssrf": "A10",
}


@pytest.mark.skipif(not _MAP.exists(), reason="0050 map not present")
def test_representative_cwe_is_a_member_of_its_category():
    m = json.loads(_MAP.read_text())
    ed = load_edition("2021")
    by_id = {c.id: c for c in ed.categories}
    mismatches = []
    for slug, cwe_str in m.items():
        cat_id = _OWASP_PREFIX.get(slug)
        if cat_id is None:  # SSDF entries etc. — out of scope
            continue
        cwe = parse_cwe_id(cwe_str)
        if cwe is not None and cwe not in by_id[cat_id].cwes:
            mismatches.append((slug, cwe_str))
    assert not mismatches, f"0050 representative CWEs not in 2021 membership: {mismatches}"
```

> If this fails, the fix is a judgment call: the 0050 representatives are broad parent CWEs (e.g. `A01→CWE-284`) that may not appear in the data-driven membership list. If so, adjust the assertion to check the parent relationship or record an accepted-divergence note — do **not** silently delete the test. Resolve during execution and document in the status doc.

- [ ] **Step 2: Run + commit**

Run: `cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/test_0050_reconciliation.py -q`

```bash
git add agents/shared/tests/unit/test_0050_reconciliation.py
git commit -m "test(0063): guard 0050 representative CWE map against shared editions"
```

---

## Task 14: Frontend + translator passthrough for the coverage manifest

**Files:**
- Modify: `backend/internal/agui/translator.go` — ensure `owasp_coverage` survives (the `result` StateSnapshot already carries the full payload; add a targeted test)
- Create: `frontend/src/components/results/OwaspCoverage.tsx`
- Modify: `frontend/src/lib/types.ts`; wire `OwaspCoverage` into the results page
- Test: `frontend/src/components/results/OwaspCoverage.test.tsx`; `backend/internal/agui/translator_owasp_test.go`

**Interfaces:**
- Consumes: the `result` event's `owasp_coverage` (Task 3/5). The live SSE stream forwards the full `result` payload in a `StateSnapshot`, so the SPA can read `owasp_coverage` directly. This task makes it visible (audit finding #7).

- [ ] **Step 1: Backend test — coverage survives translation**

Create `backend/internal/agui/translator_owasp_test.go`:

```go
package agui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTranslateResult_PreservesOwaspCoverage(t *testing.T) {
	data := json.RawMessage(`{"findings":[],"score":1,"summary":"s","owasp_coverage":{"edition":"2021","categories":[]}}`)
	evs, err := translateResult("owasp", data)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range evs {
		if len(e.Snapshot) > 0 && strings.Contains(string(e.Snapshot), "owasp_coverage") {
			found = true
		}
	}
	if !found {
		t.Fatal("owasp_coverage dropped during result translation")
	}
}
```

Run: `cd backend && go test ./internal/agui/ -run TestTranslateResult_PreservesOwaspCoverage`
Expected: PASS (the snapshot carries `data` verbatim). If it fails, adjust `translateResult` to pass the full payload through — do not strip unknown keys.

- [ ] **Step 2: Frontend type + component test**

Add to `frontend/src/lib/types.ts`:

```ts
export interface OwaspCategoryCoverage {
  id: string; name: string; mapped_count: number;
  found_cwes: string[]; found_count: number;
  status: "found" | "clean-or-undetected"; source_url: string;
}
export interface OwaspCoverageManifest {
  edition: string; cwe_stage_status: string; categories: OwaspCategoryCoverage[];
}
```

Create `frontend/src/components/results/OwaspCoverage.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { OwaspCoverage } from "./OwaspCoverage";

test("renders all categories and flags CWE stage status", () => {
  render(<OwaspCoverage manifest={{
    edition: "2021", cwe_stage_status: "completed",
    categories: [
      { id: "A03", name: "Injection", mapped_count: 33, found_cwes: ["CWE-89"], found_count: 1, status: "found", source_url: "#" },
      { id: "A01", name: "Broken Access Control", mapped_count: 34, found_cwes: [], found_count: 0, status: "clean-or-undetected", source_url: "#" },
    ],
  }} />);
  expect(screen.getByText(/A03/)).toBeInTheDocument();
  expect(screen.getByText(/A01/)).toBeInTheDocument();
  expect(screen.getByText(/1\s*\/\s*33/)).toBeInTheDocument();
});
```

- [ ] **Step 3: Implement `OwaspCoverage.tsx`**

```tsx
import type { OwaspCoverageManifest } from "../../lib/types";

export function OwaspCoverage({ manifest }: { manifest: OwaspCoverageManifest }) {
  return (
    <section className="owasp-coverage">
      <h3>OWASP Top 10:{manifest.edition} coverage</h3>
      {manifest.cwe_stage_status !== "completed" && (
        <p role="alert">CWE stage: {manifest.cwe_stage_status} — coverage may be partial.</p>
      )}
      <table>
        <thead><tr><th>Category</th><th>Found / Mapped</th><th>Status</th></tr></thead>
        <tbody>
          {manifest.categories.map((c) => (
            <tr key={c.id}>
              <td><a href={c.source_url} target="_blank" rel="noreferrer">{c.id} {c.name}</a></td>
              <td>{c.found_count} / {c.mapped_count}</td>
              <td>{c.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
```

Wire it into the results page where the OWASP audit's `result` snapshot is available (read `owasp_coverage` off the parsed result state). Also update `AuditTypeSelector` so selecting OWASP visibly notes "requires CWE (added automatically)" to reflect the `requires:["cwe"]` from `/info` (audit finding #18).

- [ ] **Step 4: Verify**

Run: `cd frontend && npx tsc --noEmit && npx vitest run src/components/results/OwaspCoverage.test.tsx`
Run: `cd backend && go test ./internal/agui/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src backend/internal/agui/
git commit -m "feat(0063): surface OWASP coverage manifest in the UI + translator passthrough test"
```

---

## Task 15: Docs + full-suite verification

**Files:**
- Rewrite: `agents/owasp/owasp_agent/skills/SKILLS.md`
- Modify: `CLAUDE.md`
- Modify: `docs/features/0063_owasp_cwe_pipeline/0063_implementation_status.md`

- [ ] **Step 1: Rewrite OWASP `SKILLS.md`** to describe the mapping contract (inputs: CWE findings; edition data files; per-category coverage output; prerequisite: CWE agent auto-injected; extensibility: add an edition file + registry line). State plainly: performs no detection.

- [ ] **Step 2: Update CLAUDE.md** — document that OWASP is a categorizer over CWE findings, CWE is auto-injected as its prerequisite, `owasp` is Optional (not in the default scan set), editions are data-file-driven (2021 default, 2025 available), and the coverage manifest rides the `result` event as `owasp_coverage`.

- [ ] **Step 3: Full affected-surface run**

```bash
cd agents/shared && PYTHONPATH=. python -m pytest tests/unit/ -q
cd ../owasp && PYTHONPATH=../shared:. python -m pytest tests/ -q
cd ../cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/ -q
cd ../../backend && go vet ./... && go test ./internal/service/ ./internal/agui/ ./internal/handler/ ./pkg/agentregistry/
cd ../frontend && npx tsc --noEmit && npx vitest run
```
Expected: all PASS. Record counts + commit SHAs in the status doc.

- [ ] **Step 4: End-to-end smoke (agent-level)**

```bash
cd agents/owasp && PYTHONPATH=../shared:. python -c "
from owasp_agent.agent import run_audit
prior=[{'category':'CWE-89','title':'SQLi','severity':'critical','file_path':'a.py','line_start':1,'line_end':1,'description':'d','check_id':'x'},
       {'category':'CWE-918','title':'SSRF','severity':'high','file_path':'b.py','line_start':1,'line_end':1,'description':'d','check_id':'y'}]
for e in run_audit('smoke','/tmp',{'edition':'2021'},prior_findings=prior):
    if 'event: result' in e or 'event: finding' in e: print(e[:180])
"
```
Expected: finding events with A03/A10 categories; result event with `owasp_coverage`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(0063): OWASP mapper SKILLS.md, CLAUDE.md, implementation status"
```

---

## Self-Review

**Audit findings addressed:**
- #1 (primary-path duplication) → Task 7 (owasp Optional) + Task 9 (deferred phase). OWASP no longer runs concurrently with CWE.
- #2 (transport ambiguity) → Task 9 uses the native `prior_findings` transport only; agent reads the param (Task 5). No config-priors path.
- #3 (E2E tests wrong path) → Task 6 E2E posts `prior_findings` in the body (the exact backend path); Task 9 has Go tests for the real dispatch.
- #4 (false multi-category test) → Task 2 test rewritten to assert list-type behavior, no unverified overlap; no "fix the data" instruction.
- #5 (cascade / partial provenance) → Task 3/5 `cwe_stage_status`; Task 9 launches OWASP even on CWE failure/absence; manifest annotates it.
- #6 (secret snippets) → Task 5 `_CARRY` excludes snippet + test; Task 9 `findingsToPriors` omits snippet (PriorFinding has no snippet field).
- #7 (manifest invisible) → Task 14 (translator passthrough test + `OwaspCoverage.tsx`).
- #8 (multi-repo DB change) → eliminated: no DB schema change (single-stream design, no new pipeline columns).
- #9 (2025 not measured) → Task 10 measures before Tasks 11–12 prescribe.
- #10 (hardcoded DETECTED_CWES) → Task 10 derives the set by scanning skills; no hardcoded list.
- #11 (dual mapping divergence) → Task 13 reconciliation guard.
- #12 (import-time crash) → Task 5 `config.py` lazy + fallback.
- #13 (SSE self-reparse) → Task 4 `result_event(extra=...)`.
- #14 (score semantics) → Task 5 reuses `compute_score`.
- #15 (FP-prone rate-limit heuristic) → Task 11 file-scoped suppression + explicit test.
- #16 (brittle grep test) → Task 6 asserts via imports/module introspection.
- #17 (`_relabel` double-assign) → Task 5 code is corrected (single assignment).
- #18 (prereq not enforced) → Task 9 `ensureCwe` auto-injects; Task 14 UI note.
- #19 (large config blobs) → eliminated with the native-transport design.

**Placeholder scan:** Task 12 is explicitly conditional on Task 10's measurement (not a placeholder — a measured branch). No TBD/TODO left.

**Type consistency:** `load_edition/Edition/Category/map_cwe/parse_cwe_id` (Task 2) used identically in Tasks 3, 5, 10, 13. `build_manifest(edition, detected, cwe_stage_status)` consistent in Tasks 3, 5. `result_event(..., extra=)` (Task 4) used in Task 5. Go: `ParseDeltaFindings` (Task 8) used in Task 9's tap; `PriorFinding.LineStart/LineEnd` (Task 9 Step 1) produced by `findingsToPriors` and consumed by the mapper. `owasp_coverage` key consistent across Tasks 5, 14.

**Note for implementer:** Tasks 1, 12 require authoritative CWE lists from official OWASP pages. The 2021 lists are provided verbatim (verified). The 2025 lists MUST be fetched from `owasp.org/Top10/2025/` at implementation time and cited per category; do not copy 2021 values.
