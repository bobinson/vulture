# OWASP Top 10 Categorizer — Skills

**This agent performs NO detection.** (Feature 0063.) It maps CWE findings
produced by the CWE agent onto OWASP Top 10 categories and reports per-category
coverage. It has no pattern-matching skills; `SKILL_MAP` and `SKILL_TOOLS` are
intentionally empty.

## Why

The OWASP Top 10 is, by OWASP's own methodology, a data-driven grouping over
CWE — each category maps to a published set of CWEs (2021 averages ~20 CWEs per
category; A10/SSRF maps to exactly one). Detecting weaknesses is the CWE agent's
job. This agent turns that shared definition into a report.

## Prerequisite

The **CWE agent is a prerequisite**. The backend runs OWASP as a deferred phase
AFTER the scan agents complete and feeds it the CWE-tagged findings via the
standard `prior_findings` transport. If OWASP is requested without CWE, the
backend adds CWE automatically. If no CWE findings arrive (CWE failed or is
unconfigured), OWASP still completes and reports zero/partial coverage annotated
with `cwe_stage_status`.

## Input

`prior_findings`: a list of CWE findings, each with `category: "CWE-<n>"`, plus
`title`, `severity`, `file_path`, `line_start`, `line_end`, `description`,
`check_id`. (Code snippets are intentionally NOT carried — they can contain
secrets.)

## Behavior

1. Load the OWASP edition (`config.edition`, default from the registry; `2021`
   or `2025`). An unknown edition falls back to the default with a notice — it
   never fails.
2. For each prior finding, parse its CWE id and map it to OWASP categories for
   the edition (a CWE may map to more than one category). Re-label the finding:
   `category` becomes the OWASP slug (e.g. `A03-injection`), the source CWE is
   preserved in `mapped_from` and `check_id` (`owasp.A03.cwe-89`), and the
   category's OWASP page is added to `references`.
3. Emit a per-category **coverage manifest** on the `result` event
   (`owasp_coverage`): for every category, the count of mapped CWEs found vs
   total mapped, plus `cwe_stage_status` (completed / partial / failed / absent).

## Configuration

- `edition` (string): OWASP edition to map against. Enum from the shared
  registry (`2021`, `2025`). Default: registry default (`2021`).
- `categories` (string[]): restrict output to these OWASP ids (e.g. `["A01",
  "A03"]`). Empty = all.

## Extensibility

Adding a future OWASP edition requires only a new data file under
`agents/shared/shared/owasp/editions/` plus one line in `registry.json`. No
change to this agent, the mapping engine, or the backend.

## Coverage note

This agent can only surface what the CWE agent detects. Per-category coverage
depth is measured and CI-gated by
`agents/cwe/tests/unit/test_owasp_coverage_floor.py`, which asserts every OWASP
category (both editions) has at least one detectable CWE.
