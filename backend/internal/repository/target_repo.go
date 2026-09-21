package repository

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
)

// Feature 0091 §10.1 — the SQL the two dialects share for the target-scoped
// reads.
//
// WHY THE FRAGMENTS LIVE HERE. Postgres and SQLite each own their query
// skeletons (the placeholder form, the casts and the window syntax differ),
// but the PREDICATES must not: "which rows are active", "which rows belong to
// the selected scans", "which rows are LLM tier" are business rules, and a
// second copy of one of them is a filter that silently answers a different
// question on the local-dev store than it does in production.
//
// THE TIER PREDICATE IS THE ONE DUPLICATION THAT CANNOT BE AVOIDED.
// model.TierOf is the single definition of the tier and the projection uses
// it, but a tier FILTER has to run in SQL — pulling every row into Go to
// classify it is exactly the "filter after loading everything" this endpoint
// exists to avoid. llmTierSQL below is that rule expressed once, in SQL, and
// it mirrors TierOf clause for clause: lower-cased, trimmed, prefix `llm`,
// everything else (including the empty string 5,750 findings carry)
// deterministic.

// sqlDialect accumulates bound arguments and renders the placeholder each one
// gets, so a fragment can be built without knowing whether it will be spliced
// into a `$n` query or a `?` one, and without any caller counting positions.
type sqlDialect struct {
	pg   bool
	args []interface{}
}

// ph binds a value and returns its placeholder.
func (d *sqlDialect) ph(v interface{}) string {
	d.args = append(d.args, v)
	if d.pg {
		return "$" + strconv.Itoa(len(d.args))
	}
	return "?"
}

// inList binds every value and renders "(p1,p2,…)". An empty list is never
// passed: SQL has no legal empty IN list, so every caller guards first.
func (d *sqlDialect) inList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, d.ph(v))
	}
	return "(" + strings.Join(parts, ",") + ")"
}

// textCol renders a column as comparable text. On Postgres the audit-id and
// lineage-id columns are UUID and the ids being matched arrive as strings; on
// SQLite they are already TEXT and the cast would be a syntax error.
func (d *sqlDialect) textCol(col string) string {
	if d.pg {
		return "COALESCE(" + col + "::text,'')"
	}
	return "COALESCE(" + col + ",'')"
}

// llmTierSQL is model.TierOf, in SQL. See the file comment for why it exists.
const llmTierSQL = "LOWER(TRIM(COALESCE(provenance,''))) LIKE 'llm%'"

// severityRankSQL orders the report the way a reader triages it: worst first.
// Anything unrecognised sorts last rather than being dropped.
const severityRankSQL = `CASE LOWER(COALESCE(severity,''))
		WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END`

// activeStatusList renders the active statuses as a bound IN list, from
// model.ActiveLineageStatuses — the ONE definition of active.
func activeStatusList(d *sqlDialect) string {
	statuses := model.ActiveLineageStatuses()
	values := make([]string, 0, len(statuses))
	for _, s := range statuses {
		values = append(values, string(s))
	}
	return d.inList(values)
}

// scanSelectionSQL narrows rows to the audits the caller selected.
//
// A lineage row records three audit attributions — the scan that FIRST saw it,
// the scan that LAST reported it, and the scan that last OBSERVED it (which
// may have confirmed the code without the model re-reporting the finding). A
// row belongs to a selected scan if any of the three names it: the question
// "what did this scan tell me about this codebase" is answered by all three,
// and matching only `first_audit_id` would drop every finding a scan
// re-reported, which is most of them.
func scanSelectionSQL(d *sqlDialect, scans []string) string {
	if len(scans) == 0 {
		return ""
	}
	first := d.inList(scans)
	latest := d.inList(scans)
	seen := d.inList(scans)
	return " AND (" +
		d.textCol("first_audit_id") + " IN " + first + " OR " +
		d.textCol("latest_audit_id") + " IN " + latest + " OR " +
		d.textCol("last_seen_audit_id") + " IN " + seen + ")"
}

// targetScopeSQL is the clause every target-scoped read carries: the target
// itself, and the merge exclusion. notMerged is a constant for the reason
// documented on it — a missed copy resurrects a duplicate silently.
//
// `keys` is the target key plus its 027-backfilled twins (see
// lineage_legacy_key.go). It is an IN list rather than an equality for the
// same reason the closure pass reads both keys: until every row of a target
// has been re-found and re-keyed, its history is split across the two
// namespaces, and scoping to one of them answers half the question.
func targetScopeSQL(d *sqlDialect, keys []string, q model.AggregateQuery) string {
	return "target_key IN " + d.inList(keys) + notMerged + scanSelectionSQL(d, q.Scans)
}

// reportFilterSQL adds the user-chosen filters on top of the target scope:
// status, tier, minimum seen count and severity. Every one of them is applied
// in SQL — the page and the `total` must both be computed from the same
// filtered set, and a filter applied in Go after the fetch would page over the
// wrong rows and count the wrong total.
func reportFilterSQL(d *sqlDialect, keys []string, q model.AggregateQuery) string {
	clause := targetScopeSQL(d, keys, q)
	if !q.IncludeTerminal {
		clause += " AND current_status IN " + activeStatusList(d)
	}
	clause += tierFilterSQL(q.Tier)
	if q.MinSeen > 1 {
		clause += " AND COALESCE(seen_count,1) >= " + d.ph(q.MinSeen)
	}
	if len(q.Severities) > 0 {
		clause += " AND LOWER(COALESCE(severity,'')) IN " + d.inList(q.Severities)
	}
	return clause
}

// tierFilterSQL renders the tier half of the filter. An unset tier is not a
// filter at all.
func tierFilterSQL(tier string) string {
	switch tier {
	case model.TierLLM:
		return " AND " + llmTierSQL
	case model.TierDeterministic:
		return " AND NOT (" + llmTierSQL + ")"
	default:
		return ""
	}
}

// tilesSelectSQL is the five headline numbers, computed in ONE aggregate pass
// over the target's rows. Five separate COUNT queries would read the same
// index five times to answer one screen.
//
// COALESCE around every SUM because SUM over no rows is NULL, and a target
// whose whole selection is empty is an ordinary case (a scan filter that
// matches nothing), not an error.
func tilesSelectSQL(d *sqlDialect) string {
	active := activeStatusList(d)
	unconfirmed := d.ph(string(model.LineageStatusUnconfirmed))
	fixed := d.ph(string(model.LineageStatusFixed))
	activeCritical := activeStatusList(d)
	critical := d.ph(string(model.SeverityCritical))
	return `COUNT(*),
		COALESCE(SUM(CASE WHEN current_status IN ` + active + ` THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN current_status = ` + unconfirmed + ` THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN current_status = ` + fixed + ` THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN current_status IN ` + activeCritical +
		` AND LOWER(COALESCE(severity,'')) = ` + critical + ` THEN 1 ELSE 0 END),0)`
}

// aggregateRowCols is the projection the report table renders. It is
// deliberately narrow: the aggregate never selects the whole lineage row,
// because the report is a table of forty rows and the columns it does not
// show are bytes across the wire for nothing.
const aggregateRowCols = `id, COALESCE(ref_number,0), COALESCE(severity,''), COALESCE(category,''),
		COALESCE(title,''), COALESCE(file_path,''), COALESCE(source_path,''),
		COALESCE(evidence_line_start,0),
		COALESCE(provenance,''), COALESCE(seen_count,1), current_status,
		first_found_at, COALESCE(latest_found_at, first_found_at)`

// aggregateOrderSQL is a TOTAL order, and it has to be: paging without one
// both duplicates and loses rows across pages, silently, on a store that is
// free to return equal rows in any order. Severity first because that is how
// the table reads, then most-recently-seen, then the id as the tiebreaker
// nothing can tie on.
const aggregateOrderSQL = " ORDER BY " + severityRankSQL +
	", COALESCE(latest_found_at, first_found_at) DESC, id"

// aggregateRowScan is one row of aggregateRowCols, after each dialect has
// resolved its own time representation (Postgres hands back TIMESTAMPTZ,
// SQLite RFC3339 text). Both dialects fill this struct and then share
// newAggregateRow, so the projection rules — the tier derivation and the
// seen-count floor — exist once.
type aggregateRowScan struct {
	id            string
	refNumber     int
	severity      string
	category      string
	title         string
	filePath      string
	sourcePath    string
	targetRoot    string
	lineStart     int
	provenance    string
	seenCount     int
	status        string
	firstFoundAt  time.Time
	latestFoundAt time.Time
}

// newAggregateRow assembles one report row from the scanned columns. The tier
// is derived here, through model.TierOf, so the projection and the closure
// rules can never disagree about what an LLM row is.
func newAggregateRow(s aggregateRowScan) model.AggregateRow {
	row := model.AggregateRow{
		LineageID: s.id, Severity: s.severity, Category: s.category, Title: s.title,
		RelPath: aggregateRelPath(s.filePath, s.sourcePath, s.targetRoot), LineStart: s.lineStart,
		Tier:      model.TierOf(s.provenance),
		SeenCount: defaultSeenCount(s.seenCount), Status: s.status,
		FirstSeenAt: s.firstFoundAt, LastSeenAt: s.latestFoundAt,
	}
	ref := model.FindingLineage{RefNumber: s.refNumber}
	row.Ref = ref.FormatRef()
	return row
}

// ─────────────────────────────────────────────────────────────────────────────
// Queries and reductions both dialects share.
// ─────────────────────────────────────────────────────────────────────────────

// tierCountQuery renders the det/llm split for every scan of a target in one
// statement.
//
// The three-way UNION is the same "a row belongs to a scan if any of its three
// audit attributions names it" rule scanSelectionSQL applies, expressed as a
// set: UNION (not UNION ALL) de-duplicates the row that is attributed to the
// same scan twice, so a finding first seen and last seen by one scan is
// counted once.
func tierCountQuery(d *sqlDialect, keys []string) string {
	part := func(col string) string {
		return `SELECT ` + d.textCol(col) + ` AS audit_id, ` + d.textCol("id") + ` AS lineage_id,
			CASE WHEN ` + llmTierSQL + ` THEN 1 ELSE 0 END AS is_llm
		   FROM finding_lineage WHERE target_key IN ` + d.inList(keys) + notMerged
	}
	first := part("first_audit_id")
	latest := part("latest_audit_id")
	seen := part("last_seen_audit_id")
	return `SELECT audit_id,
		       COALESCE(SUM(CASE WHEN is_llm = 1 THEN 0 ELSE 1 END),0),
		       COALESCE(SUM(is_llm),0)
		  FROM (` + first + ` UNION ` + latest + ` UNION ` + seen + `) u
		 WHERE audit_id <> ''
		 GROUP BY audit_id`
}

// tierCount is one scan's two-number contribution.
type tierCount struct {
	det int
	llm int
}

func scanTierCounts(rows *sql.Rows) (map[string]tierCount, error) {
	out := map[string]tierCount{}
	for rows.Next() {
		var auditID string
		var c tierCount
		if err := rows.Scan(&auditID, &c.det, &c.llm); err != nil {
			return nil, fmt.Errorf("scan tier count: %w", err)
		}
		out[auditID] = c
	}
	return out, rows.Err()
}

func applyTierCounts(scans []model.TargetScan, counts map[string]tierCount) []model.TargetScan {
	for i := range scans {
		c := counts[scans[i].AuditID]
		scans[i].DetCount = c.det
		scans[i].LLMCount = c.llm
	}
	return scans
}

// lastEventQuery resolves the most recent event of each lineage id given.
//
// ROW_NUMBER rather than a GROUP BY with a bare column: SQLite would tolerate
// the bare column next to MAX(created_at), Postgres would reject it, and the
// two dialects must run the same rule. The window is partitioned by row, so
// the work is bounded by the ids passed in — which is one page, never a
// target.
func lastEventQuery(d *sqlDialect, ids []string) string {
	in := d.inList(ids)
	// The WHERE compares the column UNCAST: `COALESCE(lineage_id::text,'')`
	// would be an expression rather than a column and would give up
	// idx_lineage_events_lineage, turning a bounded lookup into a scan of the
	// whole event table. The ids come from the page just read, so they are
	// always well-formed for the column's type. Only the PROJECTION casts, and
	// only so the value scans into a Go string on both dialects.
	// The tiebreak for equal timestamps is INSERTION order, not the id: ids are
	// random UUIDs, so `id DESC` made the newest of two same-instant events a
	// coin toss. Postgres timestamps carry microseconds and never tie in
	// practice; SQLite's (now nanosecond, once second-precision) can, and its
	// implicit rowid is the insertion sequence.
	return `SELECT lineage_id, event_type FROM (
		    SELECT ` + d.textCol("lineage_id") + ` AS lineage_id, event_type,
		           ROW_NUMBER() OVER (PARTITION BY lineage_id
		                                  ORDER BY created_at DESC, ` + d.insertionOrder() + ` DESC) AS rn
		      FROM lineage_events WHERE lineage_id IN ` + in + `
		  ) e WHERE rn = 1`
}

// insertionOrder is the column that orders rows by the sequence they were
// written: SQLite's implicit rowid; on Postgres the id, which only matters on
// a microsecond tie.
func (d *sqlDialect) insertionOrder() string {
	if d.pg {
		return "id"
	}
	return "rowid"
}

func scanLastEvents(rows *sql.Rows) (map[string]string, error) {
	out := map[string]string{}
	for rows.Next() {
		var id, eventType string
		if err := rows.Scan(&id, &eventType); err != nil {
			return nil, fmt.Errorf("scan last event: %w", err)
		}
		out[id] = eventType
	}
	return out, rows.Err()
}

func applyLastEvents(rows []model.AggregateRow, events map[string]string) {
	for i := range rows {
		rows[i].LastEvent = events[rows[i].LineageID]
	}
}

func lineageIDsOf(rows []model.AggregateRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.LineageID)
	}
	return out
}

// countScansQuery counts the scans in the selection — the denominator of the
// "seen in 2 of 5 scans" bar. With no `scans` parameter that is every scan of
// the target; with one it is the selected subset, intersected with the target
// so a stale id in a deep link cannot inflate the denominator.
func countScansQuery(d *sqlDialect, keys []string, scans []string) string {
	query := `SELECT COUNT(*) FROM audits a JOIN sources s ON a.source_id = s.id
		 WHERE ` + d.textCol("s.target_key") + ` IN ` + d.inList(keys)
	if len(scans) > 0 {
		query += ` AND ` + d.textCol("a.id") + ` IN ` + d.inList(scans)
	}
	return query
}

// seenInQuery lists the audits that saw one finding.
//
// THIS IS THE ONLY QUERY IN THE FEATURE THAT READS `findings`, and it is
// scoped to a single lineage row on the detail page.
//
// TWO SOURCES, because neither alone is the answer:
//
//   - `findings`, matched on BOTH identities: `fingerprint_v2` is the 0079
//     path-canonical id (stable across mounts) and the v1 `fingerprint` is the
//     bridge for the 31,153 persisted rows that carry no v2. Both are indexed.
//   - the lineage row's own audit attributions — first, latest and last-seen.
//     A scan that RE-READ the cited file and confirmed the evidence quote is
//     still there wrote no `findings` row (the model was told to skip known
//     issues and complied), yet it is precisely the scan that saw this
//     finding. That case IS feature 0091; leaving it out would make the
//     evidence block say "confirmed by audit X" above a list that does not
//     contain X.
//
// The second return value is false when there is nothing to look up at all.
func seenInQuery(d *sqlDialect, l *model.FindingLineage) (string, bool) {
	var clauses []string
	if idents := identityMatchSQL(d, l); idents != "" {
		// Both sides as text, and not for tidiness: `audits.id` is UUID while
		// `findings.audit_id` is TEXT (001_init), so the uncast comparison is
		// not merely slower on Postgres — it does not typecheck, and the
		// endpoint 500s the first time a row has a fingerprint.
		clauses = append(clauses, d.textCol("a.id")+" IN (SELECT f.audit_id FROM findings f WHERE "+idents+")")
	}
	if attributed := attributedAudits(l); len(attributed) > 0 {
		clauses = append(clauses, d.textCol("a.id")+" IN "+d.inList(attributed))
	}
	if len(clauses) == 0 {
		return "", false
	}
	return `SELECT ` + d.textCol("a.id") + ` FROM audits a
		 WHERE (` + strings.Join(clauses, " OR ") + `)
		 ORDER BY a.created_at DESC`, true
}

// identityMatchSQL renders the fingerprint half of the seen-in lookup, "" when
// the row carries neither identity.
func identityMatchSQL(d *sqlDialect, l *model.FindingLineage) string {
	var idents []string
	if l.FingerprintV2 != "" {
		idents = append(idents, "f.fingerprint_v2 = "+d.ph(l.FingerprintV2))
	}
	if l.Fingerprint != "" {
		idents = append(idents, "f.fingerprint = "+d.ph(l.Fingerprint))
	}
	return strings.Join(idents, " OR ")
}

// attributedAudits is the scans the lineage row itself names, de-duplicated
// and without the blanks a row that has never been re-seen carries.
func attributedAudits(l *model.FindingLineage) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 3)
	for _, id := range []string{l.FirstAuditID, l.LatestAuditID, l.LastSeenAuditID} {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// scanSeenIn always returns a non-nil slice: `seen_in` is a list the frontend
// iterates, and a null there is a crash rather than an empty section.
func scanSeenIn(rows *sql.Rows) ([]string, error) {
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan seen-in audit: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// mergeTargetCounts folds the lineage counts onto the scan-derived target
// rows, and keeps a target that has lineage rows but no audits left (its scans
// were deleted): its history is still the answer to "what was this codebase
// told", and dropping it would lose exactly the rows nothing else can reach.
// It also folds a legacy-keyed count onto the target it belongs to. Without
// that, one project appears twice for as long as any of its rows still carry
// the 027 backfill key: `stampTargetKey` moves the SOURCE to the resolved key
// on the next ingest, while the lineage rows migrate one at a time as each
// finding is re-found — and terminal rows never migrate at all, because the
// closure pass never sees them. The two halves are the same codebase, so they
// are one dashboard row with one set of numbers.
func mergeTargetCounts(targets []model.TargetSummary, counts map[string]model.TargetSummary,
	aliases map[string]string) []model.TargetSummary {
	// The scan side needs the alias too. Convergence is per SOURCE, so a
	// codebase mid-flight has one source row on the backfilled key and another
	// already re-ingested onto the resolved one. Folding only the counts left
	// the legacy scan row standing as a target of its own — the project showed
	// twice, once with the scans and no findings, once with the findings and
	// no scans, which is the split the bridge exists to hide.
	targets = foldAliasedTargets(targets, aliases)

	byKey := make(map[string]int, len(targets))
	for i := range targets {
		byKey[targets[i].TargetKey] = i
	}
	folded := map[string]bool{}
	for key, c := range counts {
		target, ok := aliases[key]
		if !ok {
			target = key
		}
		i, known := byKey[target]
		if !known {
			continue
		}
		targets[i].ActiveCount += c.ActiveCount
		targets[i].UnconfirmedCount += c.UnconfirmedCount
		targets[i].FixedCount += c.FixedCount
		folded[key] = true
	}
	for key, c := range counts {
		if !folded[key] {
			targets = append(targets, c)
		}
	}
	sortTargets(targets)
	return targets
}

// sortTargets puts the most recently scanned codebase first, with the key as
// the tiebreaker so the dashboard order is stable across reloads.
func sortTargets(targets []model.TargetSummary) {
	sort.Slice(targets, func(i, j int) bool {
		if !targets[i].LastScanAt.Equal(targets[j].LastScanAt) {
			return targets[i].LastScanAt.After(targets[j].LastScanAt)
		}
		return targets[i].TargetKey < targets[j].TargetKey
	})
}

// foldAliasedTargets rewrites every scan-derived target onto its resolved key
// and merges the rows that then collide.
//
// The merge is not a pick: scan_count is the codebase's scans under EITHER
// key, and `last_scan_at` / `last_audit_id` must travel together, because the
// dashboard opens the named audit when the row is clicked — taking the latest
// timestamp from one row and the audit id from another sends the user to a
// scan that is not the one the row describes.
//
// The display name is taken from the surviving resolved row when it has one,
// so a codebase is named after itself rather than after whichever sub-path
// happened to be re-ingested first.
func foldAliasedTargets(targets []model.TargetSummary, aliases map[string]string) []model.TargetSummary {
	if len(aliases) == 0 {
		return targets
	}
	out := make([]model.TargetSummary, 0, len(targets))
	at := map[string]int{}
	for _, t := range targets {
		key := t.TargetKey
		resolved, aliased := aliases[key]
		if aliased {
			key = resolved
		}
		i, seen := at[key]
		if !seen {
			t.TargetKey = key
			at[key] = len(out)
			out = append(out, t)
			continue
		}
		dst := &out[i]
		dst.ScanCount += t.ScanCount
		dst.ActiveCount += t.ActiveCount
		dst.UnconfirmedCount += t.UnconfirmedCount
		dst.FixedCount += t.FixedCount
		if t.LastScanAt.After(dst.LastScanAt) {
			dst.LastScanAt = t.LastScanAt
			dst.LastAuditID = t.LastAuditID
		}
		// The codebase's root is the ANCESTOR of the folded paths, never
		// whichever source sorted first. Rows arrive ordered by last scan, so
		// a sub-path scanned most recently leads — and taking its path made
		// the dashboard name the project ".vscode" instead of the repository
		// the marker was actually resolved at.
		if rootBefore(t.RootPath, dst.RootPath) {
			dst.RootPath = t.RootPath
		}
		// A git remote names a repository wherever it is checked out, so any
		// row that has one supplies it to the merged target.
		if dst.GitURL == "" {
			dst.GitURL = t.GitURL
		}
	}
	return out
}

// rootBefore reports whether candidate is a better root for a merged target
// than current.
//
// "Better" is: a real path beats none, and an ANCESTOR beats its descendant.
// Ancestry is decided by path structure, not by string length — `/a/bb` is
// shorter than `/a/b/c` in neither the sense that matters nor in characters,
// and comparing lengths would pick the wrong one for siblings. Two unrelated
// paths leave the incumbent alone: they are not two spellings of one root, and
// silently preferring either would name the codebase after a coin flip.
func rootBefore(candidate, current string) bool {
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	return isPathAncestor(candidate, current)
}

// isPathAncestor reports whether ancestor contains descendant, comparing whole
// segments so `/a/bc` is not treated as a parent of `/a/bcd`.
func isPathAncestor(ancestor, descendant string) bool {
	a := strings.TrimRight(ancestor, "/")
	d := strings.TrimRight(descendant, "/")
	if a == d {
		return false
	}
	if a == "" { // "/" is an ancestor of everything below it
		return strings.HasPrefix(d, "/")
	}
	return strings.HasPrefix(d, a+"/")
}

// aggregateRelPath renders one row's stored file_path as the report's
// `rel_path`: relative to the source that row was found under.
//
// WHY THE REPORT NORMALISES AND THE STORE DOES NOT. `file_path` serves two
// incompatible jobs. It must resolve on disk for the L5 judge's file signature
// (a bare os.stat), and it must read as a location inside the codebase. 0079
// weighed rewriting the stored value and refused, because a stored path is
// also what triage state hangs off. The report has only the second job, so it
// is the right place — and normalising here writes nothing back, moves no
// fingerprint and orphans no lineage row.
//
// It is not cosmetic. The two tiers emit different forms for the same file, so
// without this one column shows a deterministic finding at
// /home/user/…/server/app.js and the LLM finding beside it at server/app.js.
//
// A path that cannot be placed under its own source is returned UNCHANGED. A
// row recorded under a different mount, or a finding outside the tree, is a
// fact worth showing intact; mangling it into a plausible-looking relative
// path would be a lie the reader cannot detect.
func aggregateRelPath(filePath, sourcePath, targetRoot string) string {
	if filePath == "" {
		return ""
	}
	// 1. The target root is the report's coordinate system: every row on one
	//    report must be addressable the same way, including rows a SUB-PATH
	//    scan recorded. Relativising against the row's own source renders a
	//    `<root>/.vscode` scan's finding as bare `tasks.json` beside a
	//    root-scanned `server/app.js`, and nothing on screen says the first is
	//    two levels down.
	if targetRoot != "" {
		if rel := pathutil.RelToRoot(filePath, targetRoot); rel != filePath {
			return rel
		}
		// A path the row's own scan already relativised is relative to THAT
		// scan's root, not the target's. Restore the offset before giving up.
		if sourcePath != "" && !strings.HasPrefix(filePath, "/") {
			if offset := pathutil.RelToRoot(sourcePath, targetRoot); offset != sourcePath && offset != "" {
				return offset + "/" + filePath
			}
		}
	}
	// 2. No target root, or the row belongs to a different mount: its own
	//    source is the best coordinate system available.
	if sourcePath != "" {
		if rel := pathutil.RelToRoot(filePath, sourcePath); rel != filePath {
			return rel
		}
	}
	// 3. Neither placed it. Strip the run-mode prefixes (the docker bind mount,
	//    the git-ingest temp dir), which name no codebase and never belong on
	//    screen.
	if stripped, ok := pathutil.StripRunModePrefix(filePath); ok && stripped != "" {
		return stripped
	}
	// A path that cannot be placed at all is returned UNCHANGED. A row from an
	// unknown mount is a fact worth showing intact; mangling it into a
	// plausible-looking relative path would be a lie the reader cannot detect.
	return filePath
}
