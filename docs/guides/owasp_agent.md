# OWASP Agent: How It Works & How It Reports the Top 10

The OWASP agent does **not** scan code. It is a *categorizer*: it takes the
CWE findings produced by the CWE agent and maps each one onto its OWASP Top 10
category, then reports per-category coverage. This reflects how OWASP itself
defines the Top 10 — each category is a published grouping of CWEs (feature 0063).

```
Source code                         Prior findings (CWE-tagged)          OWASP report
   │                                        │                                 │
   ▼                                        ▼                                 ▼
CWE agent  ──detects──▶  findings: category="CWE-89", "CWE-798", …  ──▶  OWASP agent
(deterministic skills)                                              (maps CWE → OWASP cat)
                                                                          │
                                                                          ▼
                                              per-category findings  +  owasp_coverage manifest
                                              (A03-injection, …)        (10 categories, found/mapped)
```

The CWE agent does the heavy lifting (detection); the OWASP agent turns those
results into the OWASP taxonomy. This means OWASP coverage improves for free
whenever CWE detection improves — there is one detection engine, not two.

---

## How it works

1. **CWE is a prerequisite.** When an audit requests `owasp`, the backend
   automatically adds `cwe` and runs it **first** (OWASP is a *deferred phase*,
   not part of the concurrent scan set). The CWE-tagged findings from the scan
   are captured and passed to the OWASP agent via the standard `prior_findings`
   transport.
2. **Mapping.** For each prior finding whose category is `CWE-<n>`, the agent
   looks up the OWASP categories that CWE belongs to for the selected edition
   and re-labels the finding: `category` becomes the OWASP slug (e.g.
   `A03-injection`), the source CWE is preserved in `mapped_from`, and the
   category's OWASP page is added to `references`. A CWE can map to more than
   one category.
3. **Coverage manifest.** The agent emits a per-category manifest covering all
   10 categories — even ones with zero findings are reported (never dropped).
4. **Never fails.** A bad edition falls back to the default with a notice; an
   absent/failed CWE stage still produces a (zero/partial) manifest annotated
   with `cwe_stage_status`. The audit always completes.

---

## What it reports

**Per-finding** (one OWASP finding per CWE→category match):

| Field | Example | Meaning |
|-------|---------|---------|
| `category` | `A03-injection` | OWASP category slug (starts with the id `A03`) |
| `owasp_category_id` | `A03` | OWASP category id |
| `mapped_from` | `CWE-89` | the CWE this was derived from |
| `check_id` | `owasp.A03.cwe-89` | stable identifier |
| `file_path`, `line_start` | `app.py`, `20` | location (carried from the CWE finding) |
| `references` | `https://owasp.org/Top10/2021/A03_2021-Injection/` | the category's OWASP page |

> Code snippets are deliberately **not** carried onto OWASP findings (they can
> contain secrets).

**Coverage manifest** — attached to the `result` event as `owasp_coverage` and
persisted on the audit (so it survives reload / viewing a completed audit):

```json
{
  "edition": "2021",
  "cwe_stage_status": "completed",
  "categories": [
    {"id": "A03", "name": "Injection", "mapped_count": 33,
     "found_cwes": ["CWE-78", "CWE-89"], "found_count": 2, "status": "found",
     "source_url": "https://owasp.org/Top10/2021/A03_2021-Injection/"},
    {"id": "A05", "name": "Security Misconfiguration", "mapped_count": 20,
     "found_cwes": [], "found_count": 0, "status": "clean-or-undetected", "...": "..."}
  ]
}
```

- `mapped_count` — how many CWEs OWASP maps to this category (the denominator).
- `found_count` / `found_cwes` — how many were detected in this audit.
- `cwe_stage_status` — `completed` | `partial` | `failed` | `absent`. Anything
  other than `completed` means coverage may be incomplete; the UI flags it.

The frontend renders this manifest on the audit results page (both live and on
reload).

---

## Editions: 2021 and 2025

Both editions are supported; **each audit reports one edition** (default `2025`).
2025 restructures the list — for example SSRF (CWE-918) folds into **A01**,
injection into **A05**, and **A10** becomes *Mishandling of Exceptional
Conditions*. Select the edition in the agent config:

```json
{ "owasp": { "edition": "2025" } }
```

Optional: restrict the report to specific categories with
`{ "owasp": { "categories": ["A01", "A03"] } }` (empty = all).

The mapping data is a single source of truth in
`agents/shared/shared/owasp/editions/` (`owasp_2021.json`, `owasp_2025.json`,
`registry.json`) — CWE membership per category, copied verbatim from the
official OWASP pages. **Adding a future edition is one JSON file plus one
registry line** — no code change to the agent, mapping engine, or backend.

---

## Running it

**CLI** (the backend auto-runs CWE first):

```bash
vulture scan ./my-project --types owasp --wait          # 2025 (default)
```

**API** — create an audit with `owasp` in `types` and pick the edition:

```bash
curl -X POST "$API/api/audits" -H "Authorization: Bearer $TOKEN" \
  -d '{"source_id":"<id>","types":["owasp"],"config":{"owasp":{"edition":"2025"}}}'
```

Then open the audit's stream (or `GET /api/audits/<id>` after it completes —
`owasp_coverage` is in the response).

`GET /api/agents/owasp/info` advertises the contract: `"requires": ["cwe"]`,
`"skills": []`, and the `edition`/`categories` config schema.

---

## Coverage expectations

The OWASP agent can only surface what the CWE agent detects. Depth varies by
category (each maps to ~20 CWEs on average; the CWE agent detects a subset).
A CI floor test (`agents/cwe/tests/unit/test_owasp_coverage_floor.py`) guarantees
**every category in both editions has at least one detectable CWE**, so no
category is ever structurally blind. The end-to-end pipeline is exercised by
`agents/owasp/tests/e2e/test_owasp_over_cwe_integration.py`, which runs a
vulnerable fixture through CWE detection → OWASP mapping and asserts all 10
categories are covered for both editions.

Categories like **A04 Insecure Design** are, by OWASP's own definition, largely
design-level and not fully code-detectable — the manifest reports what was found
and leaves the rest as `clean-or-undetected` rather than implying full assurance.
