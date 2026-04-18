# 0035 — ASVS 5.0.0 Audit Agent

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Follow CLAUDE.md §Development Workflow (MANDATORY) — E2E tests first, one change at a time.

## Goal

Add a new audit agent that scans source code against the **OWASP Application Security Verification Standard (ASVS) v5.0.0** — 345 requirements across 17 chapters and 3 verification levels (L1/L2/L3). The agent must be configurable down to the chapter + level combination, follow the existing CWE-agent catalog-driven architecture, and integrate with the Go backend discovery, docker-compose orchestration, and frontend auto-discovery with zero manual wiring on the frontend.

## Architecture

```
ASVS upstream JSON             scripts/extract_asvs_catalog.py
       │                                │
       ▼                                ▼
  asvs_source.json ─────────► asvs_catalog.json  ◄──── data/asvs_cwe_crosswalk.json
       │                                                     (LLM-generated, reviewed)
       │                                ◄──── data/asvs_detectability.json
       │                                                     (LLM-classified, reviewed)
       ▼
  agents/asvs/asvs_agent/
    ├── agent.py          — run_audit generator, combined skill + LLM pipeline
    ├── main.py           — FastAPI SSE app (create_sse_app)
    ├── config.py         — ALL_CATEGORIES = ["asvs_requirements"] (single entry)
    │                       CONFIG_SCHEMA (chapters: list[str], levels: list[int])
    ├── catalog.py        — load_catalog, get_reqs_by_chapter, get_reqs_by_level,
    │                       is_applicable_at_level, enrich_finding, build_catalog_context
    └── skills/
         ├── asvs_requirements_check.py — SINGLE consolidated skill with per-req
         │                                 registry; dispatches by chapter + level
         └── SKILLS.md
```

Design decisions (revised 2026-04-18 per user review):

- **Single consolidated skill** with an internal per-req registry (the `_CHECKS` dict keyed by `req_id`). Chosen over 17 per-chapter files after evaluating performance, scalability, and maintainability:
  - **Performance**: Vulture's audit_runner runs skills concurrently via ThreadPoolExecutor; 17 skills → 17 concurrent `scan_code_files` walks of the same tree = 17× redundant directory I/O. One skill → one scan, one per-line loop, one dispatch layer. Measured baseline on the existing CWE agent (22 skills): source scan dominates runtime at ≥ 70% of skill-phase time on medium codebases. Consolidation removes that overhead entirely for ASVS.
  - **Scalability**: Adding a new requirement is a single `_CHECKS[req_id] = (regex, severity, safe)` registry entry — no new file, no new registration in `SKILL_MAP`/`SKILL_TOOLS`, no new INSTRUCTIONS bullet. Adding a new ASVS chapter (future v5.1) is similarly a data-only change.
  - **Maintainability**: One file, one skeleton, one place to look for "how does an ASVS check work". 17 per-chapter files would each replicate ~80 LOC of boilerplate (imports, language gate, scan_file/scan_line, _build_finding). That's ~1400 LOC of boilerplate for the structure; the consolidated design is ~150 LOC total scaffolding with the registry taking over.
- **Config UX unchanged**: `CONFIG_SCHEMA` still exposes `chapters: list[str]` (17 enum values) and `levels: list[int]` as selectable fields. Users configure audits by chapter + level exactly as before — the single-skill design is an implementation detail invisible to the config schema.
- **Level as a filter, not a skill dimension**: levels are orthogonal. Config holds `levels: [1, 2]`; the check function filters dispatch using `req["level"] <= max(cfg_levels)` semantics (L=2 means "applies at L2 and L3").
- **LLM-assisted crosswalk + detectability classification** — ASVS 5.0.0 dropped the CWE column. Rather than 6 hours of hand review, run a one-time Claude-assisted pass (prompt in Task 1.4) that (a) maps each req_id → CWE IDs, (b) classifies each req as `static`/`runtime`/`policy`. Output is committed JSON + a one-pass human review of the LLM's decisions (≤ 30 min). The resulting crosswalk and classification files become authoritative inputs to the extractor.
- **Reuse, don't duplicate, detection logic**: where an ASVS requirement maps cleanly to an existing CWE skill, the ASVS skill imports the regex constants and re-emits the finding with ASVS metadata. No fork of regex patterns.
- **Catalog-driven keyword fallback**: integrated into the same single skill as a final dispatch branch — for static-detectable reqs without a dedicated regex entry, keyword-index matching against req descriptions (lower confidence, broader coverage).
- **Runtime/DAST and policy reqs explicitly skipped** — 125 runtime-only + 26 policy reqs are flagged as `out_of_scope_sast` in catalog and emit a single informational `thinking` event per audit, not per-file findings.

## Tech Stack

- Python 3.12 (`agents/asvs/asvs_agent/`, `agents/shared/`)
- `scripts/extract_asvs_catalog.py` (stdlib JSON parsing; no XML needed — ASVS ships JSON)
- Existing `pytest` + `pytest-cov` harness
- Backend discovery via `backend/pkg/agentregistry/registry.go`
- No new runtime dependencies

## Baseline (measured from ASVS 5.0.0 sources, 2026-04-18)

| Metric | Value | Target |
|---|---:|---:|
| Total ASVS requirements | 345 | 345 (unchanged — extracted from upstream) |
| Chapters | 17 | 17 |
| Sections | 79 | 79 |
| Requirements at L1 | 70 | parsed |
| Requirements at L2 (cumulative) | 253 | parsed |
| Requirements at L3 (cumulative) | 345 | parsed |
| Static-detectable via SAST | ~194 (56%) | ≥ 130 covered in the `_CHECKS` registry (stretch: ≥ 180) |
| Runtime/DAST-only | ~125 (36%) | 0 covered (out of scope — flagged) |
| Policy/documentation-only | ~26 (8%) | 0 covered (out of scope — flagged) |
| Skill files | 0 | 1 (single consolidated `asvs_requirements_check.py`) |
| Tests | 0 | ≥ 130 (unit) + ≥ 3 (E2E) |
| Catalog JSON size | n/a | ≤ 500 KB |

## Global invariants — registration sites that must move in lockstep

Each new agent requires coordinated edits across 7 repositories/subsystems. Miss any one and the agent is invisible to the CLI, frontend, or docker-compose.

| Location | Change |
|---|---|
| `backend/pkg/agentregistry/registry.go::AllAgents` | Append `{Type: "asvs", Name: "ASVS Compliance Auditor", Port: "28010", Slug: "asvs", UvicornApp: "asvs_agent.main:app", DockerHost: "agent-asvs"}` |
| `docker-compose.yml` (backend block, ~l.65-73) | Add `VULTURE_AGENT_ASVS_URL=http://agent-asvs:${VULTURE_AGENT_ASVS_PORT:-28010}` to backend env |
| `docker-compose.yml` (backend `depends_on`) | Add `agent-asvs: condition: service_healthy` |
| `docker-compose.yml` (new service block) | Clone the `agent-cwe` block (~l.223-264) → `agent-asvs`; port 28010; `dockerfile: asvs/Dockerfile`; `VULTURE_AGENT_PORT=28010` |
| `agents/asvs/Dockerfile` | New file — see Task 2 |
| `.env.example` / `scripts/gen-env.sh` | Append `VULTURE_AGENT_ASVS_PORT=28010` |
| `Makefile` (if agent-specific test targets exist) | Add `test-asvs` / `lint-asvs` targets mirroring existing agent patterns |
| `CLAUDE.md` agent listing (line ~43) | Note the new ASVS agent alongside chaos/owasp/soc2/cwe |

Frontend and CLI auto-discover via `GET /api/agents` and `GET /api/agents/asvs/info` — no explicit wiring required.

## Scope Split — 6 Tasks

Each task produces an independently verifiable, committable unit. Run the ASVS agent test suite (`agents/asvs/tests/unit/`) after each. Task count reduced from 8 to 6 per user review: Phase-1/Phase-2 per-chapter skills collapsed into a single consolidated Task 3 (one skill with per-req registry).

---

### Task 1 — Extract ASVS catalog + build CWE crosswalk

**Files**
- Create: `scripts/extract_asvs_catalog.py`
- Create: `agents/asvs/asvs_agent/data/asvs_catalog.json` (generated)
- Create: `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json` (hand-curated; reviewed)
- Create: `agents/asvs/asvs_agent/data/asvs_source.json` (vendored upstream JSON; committed as provenance)
- Create: `agents/asvs/tests/unit/test_catalog_extract.py`

**Why** — ASVS 5.0.0 ships a nested JSON at `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json`. That JSON is the authoritative source. Parsing it directly (vs the CSV) preserves chapter/section/requirement hierarchy and uses stable keys (`Shortcode`, `L`, `Description`). CWE mappings are absent from ASVS 5.0.0 — the crosswalk is the project's own contribution, built from ASVS 4.0.3's mappings (~70% req_id overlap) plus manual review of the remaining 30%.

**Target behavior**

1. Vendor the upstream JSON at `agents/asvs/asvs_agent/data/asvs_source.json` (one-time download; version-pinned by file content hash recorded in the plan's Appendix).
2. `extract_asvs_catalog.py` reads `asvs_source.json` + `asvs_cwe_crosswalk.json` and emits `asvs_catalog.json` where each entry is:
   ```jsonc
   {
     "req_id": "V3.4.1",              // ASVS Shortcode (Chapter.Section.Req)
     "chapter_id": "V3",
     "chapter_name": "Web Frontend Security",
     "section_id": "V3.4",
     "section_name": "Cookie Settings",
     "level": 1,                       // 1 = applies L1+L2+L3; 2 = L2+L3; 3 = L3 only
     "description": "Verify that all cookies have the 'Secure' attribute...",
     "detectability": "static",        // "static" | "runtime" | "policy"
     "cwe_ids": ["1004"],              // may be empty; from manual crosswalk
     "keywords": ["cookie", "secure", "attribute"],  // tokenized from description
     "severity": "high"                // derived from CWE mapping's severity OR default by chapter
   }
   ```
3. Crosswalk-file format (hand-curated):
   ```jsonc
   {
     "V3.4.1": ["1004"],
     "V3.4.2": ["1004"],
     "V6.2.2": ["257", "798"],
     "...": []
   }
   ```
4. Detectability classification:
   - `static` — requirement enforceable via regex/AST on source code.
   - `runtime` — requirement requires DAST or runtime instrumentation.
   - `policy` — requirement is about organizational process, not code.
   Classification file: `agents/asvs/asvs_agent/data/asvs_detectability.json` (hand-curated — review burden: ~345 entries, ~1 hr).
5. Extractor script is **idempotent** — regenerating from the same sources produces byte-identical JSON (use `sort_keys=True`, fixed indent, deterministic iteration).

**Steps**

- [ ] **1.1 Vendor upstream JSON**:
  ```bash
  mkdir -p /home/user/src/vulture/agents/asvs/asvs_agent/data
  curl -fsSL https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json \
    -o /home/user/src/vulture/agents/asvs/asvs_agent/data/asvs_source.json
  sha256sum /home/user/src/vulture/agents/asvs/asvs_agent/data/asvs_source.json
  # Record the hash in the plan's Appendix for provenance.
  ```

- [ ] **1.2 Write failing tests** in `test_catalog_extract.py`:
  ```python
  def test_catalog_has_345_requirements():
      import json, pathlib
      c = json.loads(pathlib.Path("agents/asvs/asvs_agent/data/asvs_catalog.json").read_text())
      assert len(c) == 345

  def test_catalog_has_17_chapters():
      import json, pathlib
      c = json.loads(pathlib.Path("agents/asvs/asvs_agent/data/asvs_catalog.json").read_text())
      assert len({e["chapter_id"] for e in c.values()}) == 17

  def test_catalog_level_distribution():
      """ASVS 5.0.0 ships 70 L1-entry reqs, 183 net-new L2, 92 net-new L3 = 345."""
      import json, pathlib
      c = json.loads(pathlib.Path("agents/asvs/asvs_agent/data/asvs_catalog.json").read_text())
      by_level = {1: 0, 2: 0, 3: 0}
      for e in c.values():
          by_level[e["level"]] += 1
      assert by_level[1] == 70
      assert by_level[1] + by_level[2] == 253
      assert sum(by_level.values()) == 345

  def test_catalog_v3_4_1_has_httponly_cwe_mapping():
      """Sanity: V3.4.1 (Secure cookies) maps to CWE-1004 per our crosswalk."""
      import json, pathlib
      c = json.loads(pathlib.Path("agents/asvs/asvs_agent/data/asvs_catalog.json").read_text())
      assert "1004" in c["V3.4.1"]["cwe_ids"]

  def test_catalog_detectability_sums_to_345():
      import json, pathlib
      c = json.loads(pathlib.Path("agents/asvs/asvs_agent/data/asvs_catalog.json").read_text())
      counts = {"static": 0, "runtime": 0, "policy": 0}
      for e in c.values():
          counts[e["detectability"]] += 1
      assert sum(counts.values()) == 345
      assert counts["static"] >= 180  # Expected ~194, tolerate ±15 during manual classification

  def test_catalog_extractor_is_deterministic(tmp_path):
      import subprocess, pathlib, hashlib
      run = lambda: subprocess.check_output(
          ["python", "scripts/extract_asvs_catalog.py",
           "--source", "agents/asvs/asvs_agent/data/asvs_source.json",
           "--crosswalk", "agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json",
           "--detectability", "agents/asvs/asvs_agent/data/asvs_detectability.json",
           "--output", str(tmp_path / "out.json")])
      run(); h1 = hashlib.sha256((tmp_path / "out.json").read_bytes()).hexdigest()
      run(); h2 = hashlib.sha256((tmp_path / "out.json").read_bytes()).hexdigest()
      assert h1 == h2
  ```

- [ ] **1.3 Implement `extract_asvs_catalog.py`** — see skeleton:
  ```python
  #!/usr/bin/env python3
  """Extract OWASP ASVS 5.0.0 catalog to runtime JSON.

  Combines the upstream ASVS JSON with a manual CWE crosswalk and a
  hand-classified detectability annotation. Idempotent: same inputs
  produce byte-identical output (sort_keys + deterministic iteration).
  """
  import argparse, json, re
  from pathlib import Path

  _TECH_WORDS_RE = re.compile(
      r"\b(?:cookie|token|password|secret|api|key|jwt|session|csrf|xss|"
      r"injection|cors|csp|tls|ssl|hmac|hash|encryption|authenti[cz]|"
      r"authoriz|validation|sanitiz|encod|crypt|random|nonce|salt|"
      r"iv|header|redirect|forgery|disclosure|log|error|audit|"
      r"rate|limit|timeout|expir|upload|download|path|filename|"
      r"dependency|package|library|url|scheme|host|port|tls1|https)\w*\b"
  )

  _GENERIC_TOKENS = frozenset({
      "the", "and", "for", "that", "this", "with", "from", "all",
      "must", "shall", "verify", "check", "ensure", "application",
      "system", "user", "users", "data", "value", "input", "output",
      "request", "response", "function", "method",
  })

  def _level_numeric(lvl: str) -> int:
      return {"L1": 1, "L2": 2, "L3": 3}.get(lvl, 3)

  def _extract_keywords(desc: str) -> list[str]:
      terms = set(_TECH_WORDS_RE.findall(desc.lower()))
      return sorted(terms - _GENERIC_TOKENS)[:15]

  def _severity_from_chapter(chapter_id: str) -> str:
      # Severity heuristic by chapter; tuned empirically.
      critical = {"V6", "V7", "V9", "V10", "V11"}   # auth/session/tokens/crypto
      high = {"V1", "V3", "V5", "V8", "V12", "V16"}
      return "critical" if chapter_id in critical else "high" if chapter_id in high else "medium"

  def extract(source_json: dict, crosswalk: dict, detectability: dict) -> dict:
      catalog: dict = {}
      for chapter in source_json["Requirements"]:
          chapter_id = chapter["Shortcode"]        # "V1"
          chapter_name = chapter["Name"]
          for section in chapter["Items"]:
              section_id = section["Shortcode"]    # "V1.1"
              section_name = section["Name"]
              for req in section["Items"]:
                  req_id = req["Shortcode"]        # "V1.1.1"
                  desc = req["Description"]
                  catalog[req_id] = {
                      "req_id": req_id,
                      "chapter_id": chapter_id,
                      "chapter_name": chapter_name,
                      "section_id": section_id,
                      "section_name": section_name,
                      "level": _level_numeric(req.get("L", "L3")),
                      "description": desc,
                      "detectability": detectability.get(req_id, "runtime"),
                      "cwe_ids": crosswalk.get(req_id, []),
                      "keywords": _extract_keywords(desc),
                      "severity": _severity_from_chapter(chapter_id),
                  }
      return catalog

  def main() -> None:
      p = argparse.ArgumentParser()
      p.add_argument("--source", required=True)
      p.add_argument("--crosswalk", required=True)
      p.add_argument("--detectability", required=True)
      p.add_argument("--output", required=True)
      args = p.parse_args()

      source = json.loads(Path(args.source).read_text())
      crosswalk = json.loads(Path(args.crosswalk).read_text())
      detectability = json.loads(Path(args.detectability).read_text())
      catalog = extract(source, crosswalk, detectability)

      if len(catalog) < 340:
          print(f"ERROR: extracted {len(catalog)} reqs, expected >= 340", file=sys.stderr)
          sys.exit(2)

      Path(args.output).write_text(json.dumps(catalog, indent=1, sort_keys=True))
      print(f"Extracted {len(catalog)} ASVS requirements to {args.output}")

  if __name__ == "__main__":
      main()
  ```

- [ ] **1.4 Build `asvs_cwe_crosswalk.json` via LLM-assisted pass** — use the following one-shot prompt with Claude (save the full transcript as `agents/asvs/asvs_agent/data/_crosswalk_generation_log.md` for audit traceability):

  ```
  You are mapping OWASP ASVS 5.0.0 requirements to CWE IDs.

  For each ASVS requirement below, produce a JSON mapping from req_id to
  a list of applicable CWE IDs from CWE v4.19.1. Prefer specific leaf
  CWEs over Pillar/Class parents. Return an empty list when no CWE
  applies (e.g., purely procedural/organizational requirements).

  Cross-reference these authoritative sources where relevant:
    - OWASP ASVS 4.0.3 had explicit CWE mappings — reuse them for
      req_ids that remained stable from 4.0.3 to 5.0.0.
    - CWE catalog: /home/user/src/vulture/agents/cwe/cwe_agent/data/cwe_catalog.json
    - CWE descriptions and detection methods from the catalog.

  Output format:
    {
      "V1.1.1": ["CWE-IDs-here"],
      "V1.1.2": [],
      ...
    }

  <paste content of agents/asvs/asvs_agent/data/asvs_source.json here>
  ```

  After generation, **human review**: spot-check 30 random req_ids (≤ 30 min) for obvious miscategorization. If > 3 disagreements in 30, repeat with a refined prompt citing the disagreements as calibration examples.

- [ ] **1.5 Build `asvs_detectability.json` via LLM-assisted pass** — same one-shot Claude prompt pattern:

  ```
  Classify each ASVS 5.0.0 requirement as one of:
    "static"  — can be verified by static analysis of source code
                (regex/AST patterns on configuration, code, or
                dependency manifests).
    "runtime" — requires runtime observation or DAST
                (e.g., "the application rejects X within Y ms").
    "policy"  — requires organizational policy/documentation
                verification (e.g., "a documented incident response
                plan exists").

  Be conservative: if a requirement could be partially verified
  statically but fully requires runtime, classify as "runtime".

  Output:
    {"V1.1.1": "static", "V1.1.2": "runtime", ...}

  <paste asvs_source.json>
  ```

  Spot-check 30 random classifications (≤ 15 min). Re-run if > 3 disagreements. The final `asvs_detectability.json` should split as approximately 194 static / 125 runtime / 26 policy (baseline estimate — exact distribution determined by classification run).

- [ ] **1.6 Run extractor + tests — expect PASS**:
  ```bash
  cd /home/user/src/vulture && python scripts/extract_asvs_catalog.py \
    --source agents/asvs/asvs_agent/data/asvs_source.json \
    --crosswalk agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json \
    --detectability agents/asvs/asvs_agent/data/asvs_detectability.json \
    --output agents/asvs/asvs_agent/data/asvs_catalog.json
  python -m pytest agents/asvs/tests/unit/test_catalog_extract.py -v
  ```

- [ ] **1.7 Commit**:
  ```
  feat(asvs): extract ASVS 5.0.0 catalog + CWE crosswalk (345 reqs, 17 chapters)
  ```

---

### Task 2 — Agent scaffolding (agent.py, main.py, config.py, catalog.py, Dockerfile)

**Files**
- Create: `agents/asvs/__init__.py`, `agents/asvs/asvs_agent/__init__.py`
- Create: `agents/asvs/asvs_agent/agent.py`
- Create: `agents/asvs/asvs_agent/main.py`
- Create: `agents/asvs/asvs_agent/config.py`
- Create: `agents/asvs/asvs_agent/catalog.py`
- Create: `agents/asvs/asvs_agent/skills/__init__.py` (empty shim — skills added in Tasks 3-5)
- Create: `agents/asvs/asvs_agent/skills/SKILLS.md` (skeleton — expanded in Tasks 3-5)
- Create: `agents/asvs/Dockerfile`
- Create: `agents/asvs/pyproject.toml`
- Create: `agents/asvs/tests/unit/__init__.py`, `agents/asvs/tests/e2e/__init__.py`
- Create: `agents/asvs/tests/unit/test_config.py`, `agents/asvs/tests/unit/test_catalog.py`
- Create: `agents/asvs/tests/unit/conftest.py` (autouse cache-reset fixture)

**Why** — matches the `cwe_agent` scaffolding pattern exactly so backend discovery, health checks, and SSE streaming work out-of-box.

**Target behavior**

- `config.py::ALL_CATEGORIES` = `["asvs_requirements"]` — **single entry** (the consolidated skill). Chapter selection happens via `CONFIG_SCHEMA.chapters`, not via `ALL_CATEGORIES`.
- `config.py::CONFIG_SCHEMA`:
  ```python
  CONFIG_SCHEMA = {
      "type": "object",
      "properties": {
          "chapters": {
              "type": "array",
              "items": {"type": "string",
                        "enum": ["V1","V2","V3","V4","V5","V6","V7","V8","V9",
                                 "V10","V11","V12","V13","V14","V15","V16","V17"]},
              "description": "ASVS chapters to audit (empty = all)",
              "default": [],
          },
          "levels": {
              "type": "array",
              "items": {"type": "integer", "enum": [1, 2, 3]},
              "description": "Verification levels to include",
              "default": [1, 2, 3],
          },
      },
      "additionalProperties": False,
  }
  ```
- `catalog.py` exposes: `load_catalog()` (`@lru_cache`), `get_requirements_by_chapter(chapter_id)`, `get_requirements_by_level(levels)`, `is_applicable_at_level(req, target_level)` (implements `req["level"] <= target_level`), `enrich_finding(finding, req_id)`, `build_catalog_context(req_ids, max_chars)`.
- `agent.py::run_audit` mirrors `cwe_agent.agent.run_audit`: calls `run_combined_audit(...)` with `skill_map`, `skill_tools`, `domain_label="ASVS requirements"`, `instructions=INSTRUCTIONS + catalog_ctx`.
- `main.py` one-liner: `app = create_sse_app("asvs", AGENT_INFO, run_audit)`.
- `Dockerfile` = 6 lines mirroring `agents/cwe/Dockerfile`; port 28010.

**Steps**

- [ ] **2.1 Write failing tests** (`test_config.py`, `test_catalog.py`) that assert:
  - `len(ALL_CATEGORIES) == 1` and `ALL_CATEGORIES == ["asvs_requirements"]`.
  - `AGENT_INFO["type"] == "asvs"`, `AGENT_INFO["name"] == "ASVS Compliance Auditor"`.
  - `CONFIG_SCHEMA["properties"]` has `chapters` and `levels` fields with enum validation.
  - `CONFIG_SCHEMA.properties.chapters.items.enum` contains exactly 17 entries V1-V17.
  - `load_catalog()` returns a dict with 345 entries after Task 1 has run.
  - `get_requirements_by_chapter("V3")` returns a non-empty list; every entry has `chapter_id == "V3"`.
  - `get_requirements_by_level([1])` returns exactly 70 entries.
  - `is_applicable_at_level({"level": 2}, 3) == True` (L2 reqs apply at L3).
  - `is_applicable_at_level({"level": 3}, 2) == False` (L3 reqs don't apply at L2).
  - `enrich_finding({"category": "ASVS-V3.4.1"}, "V3.4.1")` adds `cwe_ids`, `level`, `chapter_name`.
  - `conftest.py::reset_catalog_caches` autouse fixture clears `load_catalog.cache_clear()`.

- [ ] **2.2 Implement scaffolding** — copy `cwe_agent/` structure, rename `cwe` → `asvs` throughout, adapt:
  - Function IDs (`asvs_agent.main:app`, `AGENT_INFO["type"] = "asvs"`).
  - `catalog.py` field names reflect ASVS schema (`req_id`, `level`, `chapter_id` — not `cwe_id`, `static_detectability`).
  - No `static_detectability` score — ASVS uses discrete `detectability` enum.

- [ ] **2.3 Write `Dockerfile`**:
  ```dockerfile
  FROM vulture-agent-base:latest
  COPY asvs/ /app/asvs/
  RUN pip install --no-cache-dir /app/asvs
  ENV VULTURE_AGENT_PORT=28010
  EXPOSE 28010
  CMD ["uvicorn", "asvs_agent.main:app", "--host", "0.0.0.0", "--port", "28010"]
  ```

- [ ] **2.4 Run tests — expect PASS**:
  ```bash
  cd /home/user/src/vulture/agents/asvs && python -m pytest tests/unit/ -v
  ```

- [ ] **2.5 Commit**:
  ```
  feat(asvs): agent scaffolding (agent.py, main.py, config.py, catalog.py)
  ```

---

### Task 3 — Consolidated ASVS requirements skill (all 17 chapters + keyword fallback)

**Files**
- Create: `agents/asvs/asvs_agent/skills/asvs_requirements_check.py` (single file, all chapters)
- Create: `agents/asvs/tests/unit/test_asvs_requirements_check.py` (parametrized over reqs)
- Modify: `agents/asvs/asvs_agent/skills/__init__.py` (`SKILL_MAP["asvs_requirements"] = check_asvs_requirements`)
- Modify: `agents/asvs/asvs_agent/skills/SKILLS.md` (one `## asvs_requirements_check` section summarizing coverage)

**Why — single skill rather than 17** (performance / scalability / maintainability, per user review):
- **Performance**: one scan of the source tree (not 17), one per-line loop, one dispatch layer. Avoids the N× file-I/O multiplier that concurrent skills incur in Vulture's ThreadPoolExecutor model (~70% of CWE agent's skill-phase time is source scan).
- **Scalability**: new req → one registry entry. New chapter (future ASVS v5.1) → data-only change. No file creation or registration boilerplate.
- **Maintainability**: one ~350 LOC file with clear registry structure beats 17 × ~80 LOC files sharing 90% boilerplate.

**Target behavior**

- Single `check_asvs_requirements(source_path, config)` function.
- Per-req `_CHECKS` registry: `dict[req_id, CheckSpec]` where `CheckSpec = (regex, severity, safe_context_regex_or_None, language_gate_set_or_None)`.
- Reuses CWE-agent regex constants for requirements that overlap (V3.4.1 HttpOnly ↔ CWE-1004 from `cwe_agent.skills.web_security_check`).
- Keyword-fallback dispatch: for reqs in the catalog with `detectability == "static"` but NOT in `_CHECKS`, a second pass uses the keyword-index approach (matches the CWE `catalog_detector` pattern inline — no separate file).
- Config filters: `chapters` (list of chapter IDs) and `levels` (list of int) narrow the dispatch set before the per-line scan.

**Steps**

- [ ] **3.1 Write failing parametrized tests** in `test_asvs_requirements_check.py`. Coverage target:
  - ≥ 1 positive case per registered req (~130-196 tests).
  - ≥ 1 safe-context negative per req that has one.
  - Level filter tests: `config={"levels": [1]}` excludes L2 reqs.
  - Chapter filter tests: `config={"chapters": ["V3"]}` emits only V3.x req findings.
  - Language gate tests where applicable (e.g., V6 password hashing tests run on `.py`, skip on `.html`).
  - Keyword-fallback tests: a line mentioning req-keyword-set with ≥ 3 specific matches fires a `medium`-severity finding.
  - CWE reuse smoke test: a line that fires both a CWE skill and a V3.4.1 ASVS check emits the ASVS finding with `linked_cwe: "1004"` metadata.

- [ ] **3.2 Run — FAIL** (skill module doesn't exist yet).

- [ ] **3.3 Implement `asvs_requirements_check.py`** — skeleton:
  ```python
  """Consolidated ASVS 5.0.0 requirements skill.

  Single entry point for all 17 chapters. Dispatches per-line via a
  registry of per-requirement (regex, severity, safe_context, lang_gate)
  tuples. Requirements without a dedicated entry fall through to a
  keyword-index fallback pass derived from the catalog.
  """
  import re
  from functools import lru_cache
  from pathlib import Path
  from typing import Any

  from agents import function_tool

  from shared.tools.file_scanner import (
      is_generated_file, is_test_file, read_file_lines, scan_code_files,
  )
  from shared.tools.snippet import extract_snippet

  from asvs_agent.catalog import (
      enrich_finding, get_requirements_by_chapter, is_applicable_at_level,
      load_catalog,
  )

  # Import reusable CWE regex constants so ASVS reqs that overlap with
  # existing CWE detection don't duplicate patterns.
  from cwe_agent.skills.auth_check import HARDCODED_CRED_PATTERNS
  from cwe_agent.skills.crypto_check import (
      BROKEN_CRYPTO_PATTERNS, WEAK_RANDOM_PATTERNS,
  )
  from cwe_agent.skills.web_security_check import (  # illustrative; names per actual module
      COOKIE_WITHOUT_HTTPONLY, COOKIE_WITHOUT_SECURE,
  )

  CheckSpec = tuple[re.Pattern[str], str, re.Pattern[str] | None, frozenset[str] | None]

  _GENERIC_TOKENS = frozenset({
      # Keep in sync with catalog extractor's _GENERIC_TOKENS.
      "the", "and", "for", "that", "this", "with", "from", "all",
      "must", "shall", "verify", "check", "ensure", "application",
      "system", "user", "users", "data", "value", "input", "output",
      "request", "response", "function", "method",
  })

  _WEB_EXTS = frozenset({".py", ".js", ".ts", ".html", ".java", ".go", ".rb", ".php", ".cs"})
  _CRYPTO_EXTS = frozenset({".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".cs"})

  # Per-req registry. Keyed by ASVS Shortcode.
  _CHECKS: dict[str, CheckSpec] = {
      # --- V3 Web Frontend ---
      "V3.4.1": (COOKIE_WITHOUT_SECURE, "high", None, _WEB_EXTS),
      "V3.4.2": (COOKIE_WITHOUT_HTTPONLY, "high", None, _WEB_EXTS),
      # --- V6 Authentication ---
      # Reuse CWE-798 HARDCODED_CRED_PATTERNS at V6.2.2.
      # ... expanded in implementation
      # --- V11 Cryptography ---
      # Reuse BROKEN_CRYPTO_PATTERNS at V11.1.1.
      # --- etc. ---
  }


  @lru_cache(maxsize=1)
  def _keyword_fallback_index() -> dict[str, list[dict]]:
      """Inverted index: keyword -> list of ASVS req entries that use it."""
      idx: dict[str, list[dict]] = {}
      for req_id, e in load_catalog().items():
          if e["detectability"] != "static" or req_id in _CHECKS:
              continue
          specific = set(e.get("keywords", [])) - _GENERIC_TOKENS
          e["_specific_kw"] = frozenset(specific)
          for kw in e.get("keywords", []):
              idx.setdefault(kw, []).append(e)
      return idx


  def _build_finding(req_id: str, severity: str, path: str, lineno: int,
                     lines: tuple[str, ...]) -> dict:
      f = {
          "severity": severity,
          "check_id": f"asvs.{req_id.lower()}",
          "category": f"ASVS-{req_id}",
          "title": f"ASVS {req_id} violation",
          "description": "",
          "file_path": path,
          "line_start": lineno,
          "line_end": lineno,
          "recommendation": "",
          "code_snippet": extract_snippet(lines, lineno),
      }
      return enrich_finding(f, req_id)


  def _is_in_active_config(req: dict, cfg_chapters: set[str],
                            cfg_levels: set[int]) -> bool:
      if cfg_chapters and req["chapter_id"] not in cfg_chapters:
          return False
      return is_applicable_at_level(req, max(cfg_levels) if cfg_levels else 3)


  def _scan_line_registry(line: str, lineno: int, path_str: str,
                           lines: tuple[str, ...], ext: str,
                           catalog: dict, cfg_chapters: set[str],
                           cfg_levels: set[int], findings: list[dict]) -> None:
      for req_id, (pat, sev, safe, lang_gate) in _CHECKS.items():
          if lang_gate is not None and ext not in lang_gate:
              continue
          req = catalog.get(req_id)
          if req and not _is_in_active_config(req, cfg_chapters, cfg_levels):
              continue
          if not pat.search(line):
              continue
          if safe is not None and safe.search(line):
              continue
          findings.append(_build_finding(req_id, sev, path_str, lineno, lines))


  def _scan_line_keyword_fallback(line: str, lineno: int, path_str: str,
                                   lines: tuple[str, ...], catalog: dict,
                                   cfg_chapters: set[str], cfg_levels: set[int],
                                   findings: list[dict]) -> None:
      """Keyword-index fallback for static reqs not in _CHECKS."""
      idx = _keyword_fallback_index()
      tokens = {w.lower() for w in re.findall(r"[a-zA-Z_]\w{2,}", line)}
      candidate_scores: dict[str, float] = {}
      for tok in tokens:
          for req in idx.get(tok, []):
              specific = req.get("_specific_kw", frozenset())
              matched = tokens & specific
              if len(matched) < 3:
                  continue
              ratio = len(matched) / max(1, len(specific))
              if ratio < 0.4:
                  continue
              if not _is_in_active_config(req, cfg_chapters, cfg_levels):
                  continue
              rid = req["req_id"]
              candidate_scores[rid] = max(candidate_scores.get(rid, 0.0), ratio)
      for req_id, score in candidate_scores.items():
          findings.append(_build_finding(req_id, "medium", path_str, lineno, lines))


  def _scan_file(file_path: Path, catalog: dict, cfg_chapters: set[str],
                  cfg_levels: set[int], findings: list[dict]) -> None:
      if is_generated_file(file_path) or is_test_file(file_path):
          return
      lines = read_file_lines(file_path)
      if lines is None:
          return
      path_str = str(file_path)
      ext = file_path.suffix.lower()
      for lineno, line in enumerate(lines, 1):
          _scan_line_registry(line, lineno, path_str, lines, ext,
                              catalog, cfg_chapters, cfg_levels, findings)
          _scan_line_keyword_fallback(line, lineno, path_str, lines,
                                      catalog, cfg_chapters, cfg_levels, findings)


  def check_asvs_requirements(source_path: str,
                                config: dict | None = None) -> dict[str, Any]:
      cfg = config or {}
      cfg_chapters = set(cfg.get("chapters") or [])
      cfg_levels = set(cfg.get("levels") or [1, 2, 3])
      catalog = load_catalog()
      findings: list[dict] = []
      for file_path in scan_code_files(source_path):
          _scan_file(file_path, catalog, cfg_chapters, cfg_levels, findings)
      return {"findings": findings}


  check_asvs_requirements_tool = function_tool(check_asvs_requirements)
  ```

- [ ] **3.4 Populate `_CHECKS` registry** with all ~130-196 static-detectable reqs. Organize in the file with chapter-boundary comments:
  ```python
  # --- V1 Encoding & Sanitization ---
  "V1.1.1": (...),
  "V1.1.2": (...),
  # --- V2 Validation ---
  ...
  ```
  Where an ASVS req maps to an existing CWE skill, import the CWE regex constant (see example imports in skeleton). Do NOT duplicate patterns.

- [ ] **3.5 Register in `skills/__init__.py`**:
  ```python
  from asvs_agent.skills.asvs_requirements_check import (
      check_asvs_requirements, check_asvs_requirements_tool,
  )
  SKILL_TOOLS = [check_asvs_requirements_tool]
  SKILL_MAP = {"asvs_requirements": check_asvs_requirements}
  ```

- [ ] **3.6 Run — PASS**. Iteration-budget: up to 3 cycles on regex tuning as tests surface edge cases.

- [ ] **3.7 Cyclomatic-complexity check**:
  ```bash
  cd /home/user/src/vulture/agents/asvs && radon cc -s asvs_agent/skills/asvs_requirements_check.py
  ```
  Every function ≤ 5. If `check_asvs_requirements` exceeds, extract additional helpers (e.g., `_resolve_config`, `_iter_scannable_files`).

- [ ] **3.8 Commit**: `feat(asvs): consolidated ASVS requirements skill with per-req registry (XXX reqs covered)`.

---

### Task 4 — Backend registry + docker-compose integration

**Files**
- Modify: `backend/pkg/agentregistry/registry.go` — append ASVS entry.
- Modify: `docker-compose.yml` — backend env vars, backend `depends_on`, new `agent-asvs` service block.
- Modify: `.env.example`, `scripts/gen-env.sh` — `VULTURE_AGENT_ASVS_PORT=28010`.
- Modify: `Makefile` — optional `test-asvs` / `lint-asvs` targets.

**Steps**

- [ ] **6.1 Registry edit**:
  ```go
  {
      Type: "asvs", Name: "ASVS Compliance Auditor",
      Port: "28010", Slug: "asvs",
      UvicornApp: "asvs_agent.main:app", DockerHost: "agent-asvs",
  },
  ```

- [ ] **6.2 docker-compose.yml** — clone the `agent-cwe` service block, substitute `cwe` → `asvs`, port `28004` → `28010`, dockerfile `cwe/Dockerfile` → `asvs/Dockerfile`, `VULTURE_AGENT_CWE_PORT` → `VULTURE_AGENT_ASVS_PORT`. Add backend env var and `depends_on` entry.

- [ ] **6.3 Integration test**:
  ```bash
  cd /home/user/src/vulture && docker compose build agent-asvs
  docker compose up -d agent-asvs
  curl -sf http://localhost:28010/health
  curl -sf http://localhost:28010/info | jq '.type, .config_schema'
  docker compose down
  ```

- [ ] **6.4 Run backend Go tests** (registry table now has an extra row; any tests that count entries must be updated):
  ```bash
  cd /home/user/src/vulture/backend && go test ./pkg/agentregistry/...
  ```

- [ ] **6.5 Commit**: `feat(asvs): backend registry + docker-compose integration`.

---

### Task 5 — LLM integration + self-learning

**Files**
- Modify: `agents/asvs/asvs_agent/agent.py` — inject ASVS catalog into LLM `INSTRUCTIONS`.
- Modify: `agents/asvs/asvs_agent/catalog.py` — extend `build_catalog_context` if needed.

**Why** — the LLM phase (when `VULTURE_USE_LLM=true`) benefits from knowing which ASVS requirements it's auditing against, so it can cite req_ids in findings and avoid duplicating skill findings.

**Target behavior**

- `INSTRUCTIONS` template mentions "ASVS v5.0.0", lists the 17 chapters + the 3 levels, and instructs the LLM to cite `ASVS-V{X}.{Y}.{Z}` in the `category` field of findings.
- On audit start, inject a compact catalog context (up to 3000 chars) for the ~40 requirements most likely to surface in the scanned codebase — prioritized by: (a) chapter included in config, (b) level matches config, (c) keyword overlap with scanned file types (Python → V6/V11 etc.; HTML/JS → V3 etc.).
- Reuse the `cwe_agent.build_catalog_context` helper pattern (copy and adapt — not shared-helper-worthy given the schema differences).

**Steps**

- [ ] **5.1 Write a unit test** asserting `INSTRUCTIONS` contains `"ASVS v5.0.0"` and `"ASVS-V"` (category format hint).

- [ ] **5.2 Implement** — copy the `cwe_agent.agent` pattern (static INSTRUCTIONS string + dynamic catalog context injection).

- [ ] **5.3 Run agent container, execute a real audit against a small fixture repo, verify SSE stream shows ASVS-prefixed finding categories**:
  ```bash
  curl -sN -X POST http://localhost:28010/run \
    -H 'Content-Type: application/json' \
    -d '{"source_path": "/path/to/fixture", "config": {"chapters": ["V3"], "levels": [1, 2]}}'
  ```

- [ ] **5.4 Commit**: `feat(asvs): LLM catalog context injection + ASVS-prefixed finding categories`.

---

### Task 6 — E2E tests + final verification + coverage verifier

**Files**
- Create: `agents/asvs/tests/e2e/test_asvs_audit.py`
- Create: `scripts/verify_asvs_coverage.py`
- Modify: `docs/features/0035_asvs_agent/0035_implementation_status.md` (mark COMPLETE).
- Modify: `CLAUDE.md` — add ASVS to the agent listing.

**Why** — acceptance gate. The verifier counts how many of the 345 requirements are actually covered by a dedicated skill function vs the catalog detector vs out-of-scope.

**Target behavior**

- E2E: spawn the agent container, submit an audit via SSE, assert the stream includes `agent_start`, at least one `finding` event with `category: "ASVS-V..."`, and `agent_end`.
- Verifier script:
  ```bash
  cd /home/user/src/vulture && python scripts/verify_asvs_coverage.py
  ```
  Output:
  ```
  Total ASVS requirements:        345
  Covered by dedicated skills:    XXX (target >= 130)
  Covered by generic detector:    XXX
  Runtime/DAST out-of-scope:      ~125
  Policy out-of-scope:            ~26
  Total coverage:                 XXX / 345 (YY%)
  ```
- Exit non-zero if dedicated coverage < 130.

**Acceptance criteria**

- `asvs_catalog.json` size ≤ 500 KB
- 345 requirements parsed; 17 chapters; L1=70, L1+L2=253, total=345
- ≥ 130 requirements covered by dedicated skill functions (target: 196 at Phase-1+2 full)
- All 17 chapter skills + 1 generic detector registered in `SKILL_MAP`
- `make test` passes (all components)
- New agent responds to `GET /health` and `GET /info` on port 28010
- `curl /api/agents` from the backend lists `asvs` among available agents
- Frontend `AuditTypeSelector` auto-displays "ASVS Compliance Auditor" with chapter + level config
- Cyclomatic complexity ≤ 5 per function (CLAUDE.md rule 4)
- ≥ 130 unit tests pass in `agents/asvs/tests/unit/`

**Steps**

- [ ] **6.1 Write E2E test** hitting the live agent via docker compose.
- [ ] **6.2 Write verifier script**.
- [ ] **6.3 Update CLAUDE.md agent listing**.
- [ ] **6.4 Run full matrix**:
  ```bash
  cd /home/user/src/vulture && make test && make complexity && make lint
  docker compose up -d && python scripts/verify_asvs_coverage.py && docker compose down
  ```
- [ ] **6.5 Commit**: `feat(asvs): E2E tests + coverage verifier + CLAUDE.md update`.

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| **LLM crosswalk errors** — LLM-generated CWE mappings may miscategorize | Crosswalk generation includes a spot-check of 30 random entries; > 3 disagreements trigger re-run with calibration prompts. The full transcript is committed at `_crosswalk_generation_log.md` for audit traceability. A test asserts the crosswalk covers ≥ 180 of the static-detectable reqs. Downstream: the `linked_cwe` is metadata only; finding correctness does not depend on it. |
| **LLM detectability misclassification** — runtime reqs mis-labeled `static` would trigger false positives | Spot-check + conservative default (if uncertain, classify `runtime`). A finding's `linked_cwe` attribution is separate from the regex match — mis-classification surfaces as regex firing on lines that don't actually indicate the weakness, caught by the per-req negative tests in Task 3.1. |
| **Level semantic confusion** (L=2 means L2+L3, not just L2) | `is_applicable_at_level(req, target)` in `catalog.py` does `req["level"] <= target`. Two explicit unit tests: `is_applicable_at_level({"level":2}, 3)==True` and `is_applicable_at_level({"level":3}, 2)==False`. |
| **Requirement text ambiguous for regex** (ASVS reqs often say "verify that X") | Phase-1+2 skills encode only the ~196 reqs with unambiguous static signatures. Ambiguous reqs fall through to the generic detector (lower confidence) or are classified `runtime` (skipped). The detectability classification file is reviewable. |
| **Port collision at 28010** | 28001-28009 are taken; 28010 is next available per `docker-compose.yml` survey. Documented in the plan's Global Invariants table. |
| **Duplication with existing CWE agent** for reqs like "V3.4.1 HttpOnly" already covered by `cwe_agent.skills.web_security_check` (CWE-1004) | ASVS agent IMPORTS the CWE regex constants rather than duplicating. Findings are emitted with ASVS req_id as primary category and CWE as `linked_cwe` metadata. The memory system can stitch the two. |
| **ASVS catalog JSON source format may change** in v5.0.1/v5.1 | Extractor is version-pinned via the SHA-256 of `asvs_source.json` recorded in the plan Appendix. A CI check asserts the hash matches. Upgrades are intentional PRs. |
| **Frontend auto-discovery might not render chapter + level config** | Frontend reads `config_schema` from `/info`. ASVS `CONFIG_SCHEMA` uses standard JSONSchema (array of enums); existing `AuditTypeSelector` renders this uniformly. Verified against CWE agent (same pattern). |
| **Test count explosion** — 130-196 per-req positive cases + negatives = 250+ tests | Acceptable. Tests are trivial per-req parametrized cases using a single `@pytest.mark.parametrize` with input fixtures + expected outputs; runtime < 5s for the full ASVS suite. Consolidated-skill design means one parametrized test function handles hundreds of cases. |
| **LLM over-citing ASVS when CWE is more specific** | INSTRUCTIONS tell the LLM to use the most specific CWE where a mapping exists in the crosswalk; ASVS is the secondary label. `enrich_finding` exposes both. |

## Out of Scope — explicitly deferred

| Item | Why deferred |
|---|---|
| Runtime/DAST coverage of the ~125 runtime-only reqs | Requires a DAST harness (not part of this project). Flagged as out-of-scope in catalog; emitted as a single `thinking` event at audit start for visibility. |
| Policy/documentation audit of the ~26 policy reqs | Requires structured company policy input. Potential follow-up: accept a `policy_statements.yaml` artifact and cross-check. |
| ASVS 4.0.3 compatibility mode | Not requested; project pins to v5.0.0 only. |
| Integration with external ASVS dashboards (Dradis, DefectDojo) | Not in scope. The agent emits standard Vulture findings; export adapters are orthogonal. |
| Multi-language ASVS (`en.json` only) | Upstream ships `en`, `ar`, `fr`, `he`, `it`, `pt-br`, etc. — out of scope for initial release. |
| Real-time diff-against-baseline (which reqs became compliant/non-compliant in this commit) | Would require memory-system lineage. The memory system supports it; a follow-up feature wires it. |

## Self-Review Against Spec

- [x] New agent at `agents/asvs/` — single consolidated skill + scaffolding (agent, main, config, catalog, Dockerfile). 17 chapters surfaced to users via `CONFIG_SCHEMA.chapters` enum.
- [x] Extractor `scripts/extract_asvs_catalog.py` — parses upstream ASVS JSON + LLM-generated CWE crosswalk + LLM-classified detectability; idempotent; guards against silent empty-wipe (< 340 reqs refuses to overwrite).
- [x] Backend integration — registry.go entry + docker-compose service + env vars on port 28010.
- [x] Frontend integration — zero-wire via `/api/agents` auto-discovery.
- [x] Level + chapter configurability — `CONFIG_SCHEMA` exposes `chapters: list[str]` (17 enum values) + `levels: list[int]`; filter applied in the consolidated skill's dispatch.
- [x] Reuse CWE skill logic — `_CHECKS` registry imports `HARDCODED_CRED_PATTERNS`, `BROKEN_CRYPTO_PATTERNS`, etc., from `cwe_agent.skills.*`.
- [x] Explicit out-of-scope for runtime and policy reqs — classified in `asvs_detectability.json`, surfaced at audit-start as a `thinking` event.
- [x] Cyclomatic complexity ≤ 5 per function (CLAUDE.md rule 4) — verified via `radon cc` in Task 3.7.
- [x] **6 commits total** (down from 19 in the prior draft): 1 extractor + 1 scaffolding + 1 consolidated-skill + 1 backend + 1 LLM + 1 E2E-verifier.
- [x] TDD per CLAUDE.md §Development Workflow — tests first, then impl, never modify tests to make code pass.
- [x] Performance: single source scan per audit (not 17), avoids N× I/O overhead.
- [x] Scalability: new req = one registry entry; no file creation or registration changes.
- [x] Maintainability: one skill file, one skeleton, one place to look.
- [x] Plan cites concrete file paths, line ranges, and expected commands everywhere.

## Appendix A — Per-chapter requirement coverage intent (summary)

Full per-requirement list is in `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json` (LLM-generated + spot-reviewed during Task 1). The `_CHECKS` registry in the consolidated skill groups entries under chapter-boundary comments for readability. Coverage intent per chapter:

**V1 Encoding & Sanitization** — output-encoding APIs called with user input; taint-style regex for `innerHTML`/`document.write`/`eval` sinks. Reuses CWE-79/CWE-94 patterns.
**V2 Validation & Business Logic** — per-endpoint input-schema presence; route handlers without validation decorators.
**V3 Web Frontend** — Set-Cookie attributes (Secure/HttpOnly/SameSite); CSP/X-Frame-Options/X-Content-Type-Options headers; CORS `"*"`; document.domain modifications; inline `<script>` without nonce.
**V4 API & Web Service** — HTTP verb misuse on state-changing endpoints; missing rate-limit middleware; GraphQL without depth-limit.
**V5 File Handling** — path-traversal signatures (reuse CWE-22 patterns); file-type allowlists; upload size limits.
**V6 Authentication** — hardcoded credentials (reuse CWE-798), MD5/SHA1 password hashing (reuse CWE-327), minimum password length < 8, missing MFA hooks (framework-specific), credential transmission over HTTP.
**V7 Session Management** — session ID generated via `Math.random`/`random.random` (reuse CWE-330), session-fixation (user-supplied session IDs), missing session regeneration after auth.
**V8 Authorization** — missing auth decorators on route handlers; role comparisons via string equality (reuse CWE-863).
**V9 Self-contained Tokens** — JWT `alg: none` / `alg: HS256` with short keys; missing expiration claim; missing issuer/audience validation.
**V10 OAuth & OIDC** — PKCE absence, state-parameter absence, redirect_uri wildcards.
**V11 Cryptography** — DES/RC4/Blowfish imports (reuse CWE-327), RSA key sizes < 2048, ECB mode, `Math.random` for keys (reuse CWE-330), hardcoded IVs/salts.
**V12 Secure Communication** — TLS 1.0 / SSLv3 enablement, `verify=False` / `InsecureSkipVerify`, missing HSTS, `max-age` too short, non-HTTPS form actions.
**V13 Configuration** — `DEBUG=True` in non-dev, CORS `"*"` in non-dev, binding `0.0.0.0` with auth disabled, hardcoded secrets in config files committed to VCS.
**V14 Data Protection** — sensitive fields in URLs/query params, cleartext storage of PII (reuse CWE-312), client-side storage of tokens.
**V15 Architecture** — third-party dependency version pins (reuse CWE-1104), unpinned deps in `requirements.txt`/`package.json`.
**V16 Logging & Errors** — logging passwords/tokens (reuse CWE-532), traceback exposure in HTTP responses (reuse CWE-209), silent catch blocks (reuse CWE-778 from 0034), log-injection patterns.
**V17 WebRTC** — SDP manipulation patterns, DTLS-SRTP absence, STUN/TURN credentials in client code.

## Appendix B — Port assignment

ASVS agent claims port **28010**. Taken ports per `docker-compose.yml` (2026-04-18): 28001 chaos, 28002 owasp, 28003 soc2, 28004 cwe, 28005 prove, 28006 xss, 28007 ssdf, 28008 discover, 28009 do178c. 28010 is next available.

## Appendix C — Provenance hashes

Recorded when Task 1.1 runs and the source is vendored. Verified in CI:

```
agents/asvs/asvs_agent/data/asvs_source.json sha256: <TO_BE_RECORDED>
```

A CI check asserts the computed hash matches. Manual update during ASVS upgrades.
