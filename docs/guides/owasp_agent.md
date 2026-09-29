# OWASP Agent: How It Works & How It Reports the Top 10

The OWASP agent does **not** scan code, and it emits **no findings of its own**.
It is a *labeler*: it takes the CWE-categorised findings produced by the scan
agents (CWE, XSS, SSDF, SOC2, …) and tells the backend which OWASP Top 10
categories each CWE belongs to. The backend attaches those categories to the
findings as **labels**, then reports per-category coverage. This reflects how
OWASP itself defines the Top 10 — each category is a published grouping of CWEs
(feature 0063; labels since feature 0096).

```
Source code                    Prior findings (CWE-categorised)           OWASP agent
   │                                        │                                 │
   ▼                                        ▼                                 ▼
scan agents ──detect──▶ findings: category="CWE-89", "CWE-798", … ──▶ edition table
(cwe, xss, ssdf, …)                                                  CWE-89 → A05, CWE-798 → A07, …
                                                                          │
                                                                          ▼
backend: labels the final, deduplicated findings by category  +  owasp_coverage manifest
         (one row per weakness, carrying compliance_labels)      (10 categories, found/mapped)
```

The scan agents do the heavy lifting (detection); the OWASP agent supplies the
OWASP taxonomy. OWASP coverage therefore improves for free whenever CWE
detection improves — there is one detection engine, not two — and a weakness is
persisted, counted and triaged **once**, however many OWASP categories name it.

---

## How it works

1. **CWE is a prerequisite.** When an audit requests `owasp`, the backend
   automatically adds `cwe` and runs it **first** (OWASP is a *deferred phase*,
   not part of the concurrent scan set). The CWE-categorised findings (category
   `CWE-<n>`) of every scan agent's finished result are captured and passed to
   the OWASP agent via the standard `prior_findings` transport.
2. **Negotiation.** The backend sends `"accepts_mapping": 1` as a top-level
   field of the OWASP agent's `/run` request, never inside `config`. A pre-0096
   backend forwards user `config` keys to agents, so a capability read from
   `config` could switch the agent into mapping mode against a backend that
   would read its empty answer as "everything fixed". The agent therefore
   ignores `config.accepts_mapping` (and this backend strips it from every
   agent's config). Only the integer `1` selects a mapping; anything else,
   including a backend that predates labels, gets the legacy answer (below).
   The mode is negotiated, never guessed, so a version mismatch in either
   direction degrades to the legacy shape rather than losing data.
3. **Mapping.** The agent answers with the edition's **full** CWE→category
   table and the effective category filter, plus the coverage manifest and a
   score. No `finding` events, and `findings: []` on the result. The presence
   of the `mapping` member, whatever its value, marks the answer: such a result
   persists none of its rows, and the run stays in mapping mode even if a later
   snapshot from the agent is legacy.
4. **Labelling.** The backend validates the table (it accepts one only from the
   agent it dispatched as `owasp`) and applies it to the run's final,
   deduplicated finding set by `category`. Every surviving CWE-categorised
   finding whose CWE the edition maps gets one label per OWASP category (a CWE
   can map to more than one). A dedup survivor is also labelled from the CWE
   ids of the rows it absorbed, so their categories are not lost with them;
   each label's `cwe` names the id it came from. CWE ids are compared without
   leading zeros (`CWE-089` is `CWE-89`). A finding whose CWE the edition does
   not map gets no OWASP label.
5. **Coverage manifest.** Reported for all 10 categories — even ones with zero
   findings (never dropped). The backend recomputes the "found" and "unmapped"
   halves from the labels it persisted, so the report never counts a CWE whose
   only finding deduplication removed.
6. **Never fails.** A bad edition falls back to the default with a notice; an
   absent/failed CWE stage still produces a (zero/partial) manifest annotated
   with `cwe_stage_status`. An invalid mapping labels nothing; the audit always
   completes.

The wire contract is specified in
[`docs/architecture/agent_protocol.md`](../architecture/agent_protocol.md)
("Mapping result (v1)").

---

## What it reports

### Labels on findings

Each labelled finding carries `compliance_labels` — in `GET /api/audits/<id>`,
the CLI's JSON output and the MCP tools (target aggregate rows carry the
lineage form, below):

```json
{
  "agent_type": "cwe",
  "category": "CWE-798",
  "title": "Hardcoded credential",
  "file_path": "config/settings.py",
  "compliance_labels": [
    {"framework": "owasp", "edition": "2025", "category_id": "A07",
     "category_name": "Authentication Failures", "cwe": "CWE-798"}
  ]
}
```

| Field | Example | Meaning |
|-------|---------|---------|
| `framework` | `owasp` | the compliance framework |
| `edition` | `2025` | the OWASP edition the label belongs to |
| `category_id` | `A07` | OWASP category id (meaningful only with its edition: `A03` is Injection in 2021, Software Supply Chain Failures in 2025) |
| `category_name` | `Authentication Failures` | the category's name in that edition |
| `cwe` | `CWE-798` | the finding category the label was derived from |

The finding keeps its own agent, category, `check_id`, fingerprint, location
and validation verdict — a label is not a row. If `categories` restricts the
audit, findings carry only the labels in that subset.

### The mapping object

The agent's `result` event carries:

```json
"mapping": {
  "version": 1,
  "framework": "owasp",
  "edition": "2025",
  "selected": ["A07"],
  "table": {
    "CWE-798": [{"id": "A07", "name": "Authentication Failures"}],
    "CWE-89":  [{"id": "A05", "name": "Injection"}]
  }
}
```

- `table` is every CWE the edition maps (2025: 249, 2021: 196), independent of
  `selected`. Entries are `{id, name}` only; no source text travels.
- `selected` is the effective `categories` filter (`[]` = all).
- The presence of the object is what marks the answer as a mapping, even with
  an empty table.

### Lineage

The OWASP agent owns **no** lineage, in any mode: the backend keeps every
mapper agent out of the lineage pass, so its result never creates, re-sights
or closes a lineage row, and its empty `findings` can never be read as
"fixed". Each labelled finding's own lineage row (its
`VLT-` ref) records the labels per edition as `compliance_labels`, keyed
`framework:edition` with the **full** edition's category ids:

```json
{"owasp:2025": ["A07"], "owasp:2021": ["A07"]}
```

A key is replaced only when a run with that edition's mapping sights the
finding; a CWE-only scan, a run of the other edition, or a `categories` subset
leaves the other keys as they were.

Lineage rows that existed before the upgrade carry **no** labels: the column
starts empty, and the fold described below does not move a folded OWASP row's
category onto its twin. A row is labelled the first time an OWASP-enabled scan
with an upgraded agent sights it, so run one per target before relying on the
label filters. A row that is never sighted again, such as a fixed finding, stays
unlabelled.

OWASP lineage rows written before labels existed (one per OWASP copy row) are
folded into their twins by migration 031 at backend start: each is merged into
the live lineage row of the finding it was copied from (same target, same file
relative to the target, same title without the `[Axx] ` prefix; a `cwe` row
preferred), with a `merged` event on both rows so the history stays readable
from the twin. A row with no twin is retired. The twin's status, notes and
ticket are never changed; if a triaged OWASP row disagrees with its twin, the
migration aborts and the backend does not start until the named rows are
reconciled. SQLite stores run the same fold once, recorded in its
`data_migrations` table; the step waits (and retries on the next start) while
any live lineage row or source is still missing its target key.

**If the upgrade stops on a disagreement.** The error names every pair
(`VLT-0042 false_positive vs twin VLT-0017 open; ...`), and the new backend
will not start, so its UI and API are not available to fix them. The fold ran
in one transaction and wrote nothing; only the new, nullable
`compliance_labels` columns remain (migration 030; SQLite adds the same
columns), which the previous release ignores. So:

1. Start the previous release against the same database.
2. For each named pair, make the two statuses equal, in the UI or with
   `PATCH /api/lineage/{id}`. Set the twin to the OWASP row's status to keep
   that decision, or set the OWASP row to the twin's status to drop it.
3. Start the new release again.

To avoid the stop, look before upgrading for OWASP lineage rows
(`agent_type = owasp`) in `false_positive`, `accepted_risk` or `resolved` whose
twin (same target, same file, same title without the `[Axx] ` prefix) has a
different status. The migration's own check is the authoritative one.

### Coverage manifest

There are two copies of `owasp_coverage`, and they can differ:

- **Streamed** (provisional) — on the agent's `result` event, forwarded
  unchanged. It is the agent's own count over the priors, taken before
  deduplication, over every category whatever `categories` selects, with no
  `selected` key. A live SSE consumer, or a client attaching within the
  broadcast TTL, sees this one.
- **Persisted** — on the audit (GET `/api/audits/{id}`, and the synthesized
  replay once the TTL has passed), so it survives reload and viewing a
  completed audit. The backend recomputes it from the labelled findings as
  described below. This is the authoritative copy (**persisted**): an SSE consumer should
  re-read the audit once it is terminal, as the results page does.
  Those two responses serve it **triage-aware**: findings marked false
  positive are left out when the audit is read (see *False positives* below),
  while the stored copy stays the record of the scan.

The persisted shape:

```json
{
  "edition": "2025",
  "cwe_stage_status": "completed",
  "categories": [
    {"id": "A05", "name": "Injection", "mapped_count": 37,
     "found_cwes": ["CWE-78", "CWE-89"], "found_count": 2, "status": "found",
     "source_url": "https://owasp.org/Top10/2025/A05_2025-Injection/"},
    {"id": "A02", "name": "Security Misconfiguration", "mapped_count": 16,
     "found_cwes": [], "found_count": 0, "status": "clean-or-undetected", "...": "..."}
  ]
}
```

- `mapped_count` — how many CWEs OWASP maps to this category (the denominator),
  from the agent's edition data.
- `found_cwes` / `found_count` / `status` — the distinct CWEs among the
  persisted findings labelled with this category, recomputed by the backend.
- `selected` — written only as `false`, on a category the audit's `categories`
  filter excluded. Its findings carry no label for it, so its found values are
  empty by choice: `found_count: 0` and `status: "clean-or-undetected"` there
  mean *not checked*, not clean. The results page shows such a category as
  "not selected". A selected category, or an audit with no filter, has no
  `selected` key. Before labels, the agent counted every category whatever
  the filter, so an older audit's manifest never carries this key and reports
  found values for unselected categories too.
- If the backend rejects the agent's mapping, or the manifest names another
  edition than the mapping, no label backs it: every category's `found_cwes` /
  `found_count` / `status` is cleared to empty / `0` / `clean-or-undetected`,
  `unmapped_cwes` to empty, and no `selected` key is written. A manifest the
  backend cannot read is not persisted.
- `unmapped_cwes` / `unmapped_count` — CWEs among the persisted findings that
  no category of the edition maps, recounted by the backend.
- Only the `owasp` agent's snapshot can supply the manifest (backend and
  results page alike).
- `cwe_stage_status` — `completed` | `partial` | `failed` | `absent`. Anything
  other than `completed` means coverage may be incomplete; the UI flags it.
- `false_positive_count` — how many distinct findings carrying this
  category's label are marked false positive; `0` when none. Present on every
  category of a labelled audit's manifest as served; absent from the streamed
  copy and from audits run before labels.

**False positives.** A finding counts as a false positive when its own
lineage row (matched on `fingerprint_v2` first, then `fingerprint`, within the
finding's agent) has status `false_positive`. Such findings are left out of
`found_cwes` / `found_count` / `status`, so a category found only through them
reads `clean-or-undetected`, and an unmapped CWE is dropped from
`unmapped_cwes` once every finding categorised with that CWE is marked.
`accepted_risk` and `resolved` findings, a `likely_fp` validation verdict, and
findings with no lineage row still count. The adjustment is made each time the audit is read
and nothing is written, so clearing the mark restores the count. It applies
only to labelled audits: an older audit's manifest, or one served when lineage
or the audit's findings cannot be read, is returned exactly as stored.

The results page renders the streamed manifest while the run is live and the
persisted one once the audit is terminal. A category with marked false
positives says how many; saving a status in the findings table re-reads the
audit, so the card updates without a reload. A category is a toggle for the
findings table's OWASP filter only when some finding carries its label; each
labelled finding shows a chip per OWASP category. During a live run the page
applies the streamed mapping to the rows it has streamed so far, so chips
appear early; those rows are pre-dedup and provisional, and the persisted rows
replace them when the audit is terminal.

### Filtering by category

Filter by label, not by agent:

- **Target aggregate:** `GET /api/targets/<key>/aggregate?framework=owasp&category=A07&edition=2025`.
  The three parameters go together: any one without the others, or a
  malformed value, is a 400 (category ids differ between editions, and the
  backend never guesses one). Every response carries `label_editions`
  (`[{framework, edition, categories}]`): the editions and categories the
  target's lineage rows carry within the selected scans, any status, not
  narrowed by the filter, newest edition first. The target report offers its
  filter from it; a link with `?owasp=A07` and no edition uses the newest.
- **MCP:** `vulture_get_findings` and `vulture_search_findings` take
  `framework="owasp"`, optionally `category="A07"` and `edition="2025"`. With
  `framework`, older audits' OWASP copy rows match too, each returned with one
  label marked `"legacy": true` (see `mcp/README.md`).
- `agent_type=owasp` is always a literal agent filter: on audits run with
  labels it matches nothing.

The target aggregate filters lineage rows by their labels, and existing rows
have none at upgrade (see *Lineage*). Until an OWASP-enabled scan has sighted a
target's findings, the `framework` filter returns nothing for that target; an
empty answer then means "not yet labelled", not "no OWASP findings".

### Comparing audits and CI gates

`GET /api/audits/{id}/comparison` leaves the older audit's OWASP copy rows out of
the diff when the newer audit is in mapping mode (it ran `owasp` and holds no
OWASP rows), so the copies are not reported as fixed. They are counted in
`excluded_legacy_copies` (omitted when 0), and the two counts reconcile:
`previous_findings_count` = persistent + changed + fixed, and
`current_findings_count` = persistent + changed + new.

`vulture scan --exit-on <severity>` counts findings, one per weakness; labels
never add to it. When it fails the build it says why on stderr:
`Exit 1: <n> finding(s) at or above <severity> (--exit-on)`.

### Legacy shape (older audits, and version skew)

Audits run before labels, and any run where the agent was not sent
`accepts_mapping: 1` (or predates it), hold one OWASP **copy row** per
CWE→category match, with `agent_type = owasp`, `category` set to the OWASP
slug (e.g. `A03-injection`), a `check_id` such as `owasp.A03.cwe-89`, the source
CWE in `mapped_from`, the category's OWASP page in `references`, and no code
snippet. The legacy answer is kept for one release to cover version skew and is
then removed. The results page still lists an older audit's OWASP rows, but
after the upgrade they show no VLT ref or triage status: migration 031 folded
their lineage into the twin finding's row, or retired it (see *Lineage*). The
same holds for `/api/audits/{id}/lineage` and the MCP lineage enrichment. Use
the twin's ref and timeline for their history.

An upgraded backend running an **older OWASP agent** still receives copy rows.
They are persisted as findings, in their legacy shape and without labels, but
they create, update and close **no** lineage rows: the OWASP agent never owns
lineage, in any mode. The findings they copy keep their own lineage as usual,
and the OWASP lineage rows from before the upgrade were already folded by
migration 031, so version skew leaves no orphaned OWASP lineage behind. What
skew does cost: such an audit holds copy rows, so the audit cache never serves
it to a new request that includes `owasp` (every such request runs fresh), its
counts include the copies, and nothing is labelled. **Upgrade the OWASP agent
together with the backend.**

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
`{ "owasp": { "categories": ["A01", "A03"] } }` (empty = all). The filter
narrows the labels on this audit's findings; the table the agent returns, and
so the labels kept on lineage, always cover the whole edition.

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
`owasp_coverage` is in the response, without findings marked false positive,
and each labelled finding carries
`compliance_labels`). The CLI's human summary prints per-category counts under
an "OWASP Top 10:<edition>" heading, and its JSON output carries
`compliance_labels` on each finding.

`GET /api/agents/owasp/info` advertises the contract: `"requires": ["cwe"]`,
`"skills": []`, and the `edition`/`categories` config schema.

---

## Coverage expectations

OWASP labels can only cover what the scan agents detect. Depth varies by
category (each maps to ~20 CWEs on average; the CWE agent detects a subset).
A CI floor test (`agents/cwe/tests/unit/test_owasp_coverage_floor.py`) guarantees
**every category in both editions has at least one detectable CWE**, so no
category is ever structurally blind. The end-to-end pipeline is exercised by
`agents/owasp/tests/e2e/test_owasp_over_cwe_integration.py`, which runs a
vulnerable fixture through CWE detection → OWASP mapping and asserts all 10
categories are covered for both editions.

Categories like **Insecure Design** (A04 in 2021, A06 in 2025) are, by OWASP's own definition, largely
design-level and not fully code-detectable — the manifest reports what was found
and leaves the rest as `clean-or-undetected` rather than implying full assurance.
