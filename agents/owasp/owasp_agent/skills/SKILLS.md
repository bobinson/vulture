# OWASP Top 10 Categorizer — Skills

**This agent performs NO detection.** (Feature 0063.) It maps CWE-categorised
findings — produced by every scan agent, the CWE agent chief among them — onto
OWASP Top 10 categories and reports per-category coverage. It has no pattern-matching skills; `SKILL_MAP` and `SKILL_TOOLS` are
intentionally empty.

## Why

The OWASP Top 10 is, by OWASP's own methodology, a data-driven grouping over
CWE — each category maps to a published set of CWEs (2021 averages ~20 CWEs per
category; A10/SSRF maps to exactly one). Detecting weaknesses is the CWE agent's
job. This agent turns that shared definition into a report.

## Prerequisite

The **CWE agent is a prerequisite**. The backend runs OWASP as a deferred phase
AFTER the scan agents complete and feeds it, via the standard `prior_findings`
transport, the CWE-categorised findings of EVERY scan agent (the CWE agent's,
and e.g. the XSS agent's CWE-79 rows), taken from each agent's finished result
snapshot. If OWASP is requested without CWE, the
backend adds CWE automatically. If no CWE findings arrive (CWE failed or is
unconfigured), OWASP still completes and reports zero/partial coverage annotated
with `cwe_stage_status`.

## Input

`prior_findings`: a list of CWE-categorised findings, each with
`category: "CWE-<n>"`, plus `title`, `severity`, `file_path`, `line_start`,
`line_end`, `description`, `check_id`, and the evidence fields `provenance`,
`validation_status`, `validation_confidence` and `validation` (the legacy
answer carries them onto its copies; a carried `validation` blob is scrubbed of
snippet-bearing extras and of the twin's `window` check). Code snippets are
intentionally NOT carried — they can contain secrets.

`accepts_mapping` (top-level /run field, NOT a config key): the mapping-result
version the backend can consume, written by the backend's agent proxy for the
OWASP agent only and passed to `run_audit` as the `accepts_mapping` keyword.
See *Mapping mode*.

## Behavior

1. Load the OWASP edition (`config.edition`, default from the registry; `2021`
   or `2025`). An unknown edition falls back to the default with a notice — it
   never fails. The notice echoes at most 32 characters of the value,
   `repr`-quoted (a non-scalar is named by its type only).
2. Answer in one of two modes, chosen per request by negotiation (feature
   0096). The mode is never inferred; it is what the backend asked for.
3. Emit a per-category **coverage manifest** on the `result` event
   (`owasp_coverage`) in both modes, identical for the same priors: for every
   category, the count of mapped CWEs found vs total mapped, plus
   `cwe_stage_status` (completed / partial / failed / absent), and the detected
   CWEs no category maps (`unmapped_cwes`).

### Mapping mode (top-level `accepts_mapping` is the integer `1`)

The backend advertises the mapping-result version it can consume as the
integer `accepts_mapping`, a TOP-LEVEL field of the /run body beside `run_id`,
`config` and `prior_findings`. It is deliberately **out of band**: a pre-0096
backend forwards arbitrary user `config` keys to agents, so a capability read
from `config` could be claimed by a user on a backend that would then read the
zero-finding answer as "every OWASP issue was fixed" and close OWASP lineage.
`config.accepts_mapping` is therefore **ignored** (and this backend strips it
from every agent's config). Only a strict JSON integer `1` qualifies — `true`,
`1.0` and `"1"` do not. When it is `1` the agent emits **no findings** — no
`finding` events and `findings: []` on the result — and returns the edition's
CWE→category table instead. The backend labels its final, deduplicated
CWE-categorised findings (from every scan agent) with that table, so each
weakness is persisted, counted and triaged once, carrying an OWASP label such
as `A07`, rather than duplicated as an OWASP row.

```json
"mapping": {
  "version": 1,
  "framework": "owasp",
  "edition": "2025",
  "selected": ["A07"],
  "table": {"CWE-798": [{"id": "A07", "name": "Authentication Failures"}], "...": []}
}
```

- `table` is the **full** edition table — every CWE the edition maps (2025:
  249, 2021: 196) — whatever `categories` selects, so the backend can keep
  per-edition labels on lineage across category subsets. Entries are `{id,
  name}` only.
- `selected` is the effective `config.categories` filter (`[]` = all): the
  edition's own category ids, in the order given, each once. The backend
  narrows the labels on findings to it, and rejects a whole mapping over one
  entry that is not a category id, so anything else in the filter (another
  agent's vocabulary, a lowercase or unknown id, a non-string, a filter that is
  not a list) is dropped with a notice that counts it without echoing it. A
  filter left with no usable id selects nothing — `["A00"]`, an id no edition
  has — as the legacy answer's does; it never widens to all.
- A prior with a missing, empty or non-string `severity` is scored as `medium`,
  the default the legacy answer gives its copy row.
- The mapping is present, full table included, even when no priors arrive.
- No prior finding's text travels in it — only edition knowledge.
- **Summary:** `Mapped N finding(s) into k/T OWASP Top 10:<edition>
  categories.` — `N` is the scored priors below, `T` the selected categories of
  the edition (every category of the edition when nothing is selected; `0` for
  a filter that selects nothing) and `k` those of them with a found CWE.
- **Score:** `compute_score` over the DISTINCT priors that map to at least one
  selected category — one entry per prior however many categories it maps to,
  a verbatim repeat counted once — against the number of priors received. It
  is a pre-dedup figure: the agent never sees the backend's final finding set.

### Legacy mode (top-level `accepts_mapping` absent, `0`, or anything but the integer `1`)

Unchanged from feature 0063 — byte for byte, summary text included (its
`k/10` counts found categories whether selected or not; that defect is kept
because the answer is pinned for older backends, and fixed in mapping mode), kept for one release so an older backend (which
would read a zero-finding OWASP result as "every OWASP issue was fixed") keeps
working. For each prior finding, parse its CWE id and map it to OWASP
categories for the edition (a CWE may map to more than one category), and emit
a re-labelled copy: `category` becomes the OWASP slug (e.g. `A03-injection`),
the source CWE is preserved in `mapped_from` and `check_id`
(`owasp.A03.cwe-89`), and the category's OWASP page is added to `references`.
The score is `compute_score` over the emitted copies.

## Configuration

- `edition` (string): OWASP edition to map against. Enum from the shared
  registry (`2021`, `2025`). Default: registry default (`2025`).
- `categories` (string[]): restrict output to these OWASP ids (e.g. `["A01",
  "A03"]`). Empty = all. In mapping mode it narrows the labels (echoed as
  `selected`), never the table.

`accepts_mapping` is NOT a configuration option: it is a top-level request
field the backend sets (see *Input*); a `config.accepts_mapping` is ignored.

## Extensibility

Adding a future OWASP edition requires only a new data file under
`agents/shared/shared/owasp/editions/` plus one line in `registry.json`. No
change to this agent, the mapping engine, or the backend.

## Coverage note

This agent can only surface what the CWE agent detects. Per-category coverage
depth is measured and CI-gated by
`agents/cwe/tests/unit/test_owasp_coverage_floor.py`, which asserts every OWASP
category (both editions) has at least one detectable CWE.
