package model

import "time"

// Feature 0091 §10.1 — the target-scoped read side.
//
// Everything the product could show before this file was scoped to ONE audit:
// `/api/audits/{id}` is one scan's findings, `/api/audits/{id}/comparison` is
// one scan against its predecessor. Neither answers the question a user
// actually has — "what has this codebase ever been told about itself, and what
// is still true?" — because neither is scoped to a CODEBASE at all.
//
// These structs ARE the wire contract. The frontend (`frontend/src/lib/types.ts`)
// is written against these exact json names, so a rename here is a silent
// breakage there.

// TargetSummary is one row of GET /api/targets: a codebase the installation
// has scanned, with the counts a dashboard needs to rank it.
//
// The counts come from `finding_lineage`, NOT from the last scan's findings.
// The number a user needs is "34 open issues in this codebase", not "34
// findings in the most recent run" — the two differ by exactly the findings an
// older scan raised and the newest one did not re-report.
type TargetSummary struct {
	TargetKey   string `json:"target_key"`
	DisplayName string `json:"display_name"`
	ScanCount   int    `json:"scan_count"`
	// ActiveCount is ActiveLineageStatuses(), so `unconfirmed` and
	// `regression` are counted and the four terminal states are not.
	ActiveCount      int       `json:"active_count"`
	UnconfirmedCount int       `json:"unconfirmed_count"`
	FixedCount       int       `json:"fixed_count"`
	LastScanAt       time.Time `json:"last_scan_at"`
	LastAuditID      string    `json:"last_audit_id"`

	// RootPath and GitURL are inputs to DisplayName, not part of the wire
	// shape: the repository reads them, the service turns them into a name a
	// human can read, and neither reaches the client. They are carried on this
	// struct rather than on a parallel one because a second struct differing
	// by two fields is where the two copies drift.
	RootPath string `json:"-"`
	GitURL   string `json:"-"`
}

// TargetScan is one entry of GET /api/targets/{key}/scans — the history rail.
//
// SubPath and the det/llm split are the two things that make the rail legible.
// A `.vscode` scan and a root scan are the SAME target (§7.2) and would
// otherwise be indistinguishable, which is exactly how the reference
// incident's two scans looked identical; and the two tiers obey different
// closure rules, so "what did this scan contribute" is a two-number answer.
type TargetScan struct {
	AuditID   string    `json:"audit_id"`
	CreatedAt time.Time `json:"created_at"`
	SubPath   string    `json:"sub_path"`
	GitBranch string    `json:"git_branch"`
	DetCount  int       `json:"det_count"`
	LLMCount  int       `json:"llm_count"`
	Types     []string  `json:"types"`

	// Path is the directory the scan actually stood in. SubPath is derived
	// from it against the target's root; the raw path stays server-side.
	Path string `json:"-"`
}

// AggregateQuery is the parsed and normalised form of the aggregate request's
// query string. The handler parses, the service normalises (page floors,
// severity lower-casing), the repository turns it into SQL — so nothing below
// the handler ever re-reads a raw parameter.
type AggregateQuery struct {
	TargetKey string
	// Scans narrows the report to a subset of the target's audits. Empty =
	// every scan of the target.
	Scans []string
	// IncludeTerminal is `status=all`: fixed, resolved, false_positive and
	// accepted_risk join the active four. A closed finding is closed history,
	// not deleted history.
	IncludeTerminal bool
	// Tier is "", TierDeterministic or TierLLM.
	Tier string
	// MinSeen keeps rows seen by at least this many scans. <= 1 is no filter.
	MinSeen int
	// Severities is a lower-cased allow-list; empty = every severity.
	Severities []string
	Page       int
	PageSize   int
}

// Offset is the SQL offset for the requested page. Page is 1-based and
// already floored at 1 by the handler, so this can never be negative.
func (q AggregateQuery) Offset() int {
	return (q.Page - 1) * q.PageSize
}

// AggregateRow is one unique FINDING in the aggregate report — not one
// occurrence of it. A finding seen by five scans is one row with SeenCount 5;
// an implementation that joins per scan returns it five times and the "40
// unique findings" headline silently becomes a scan count multiplied by a
// finding count.
type AggregateRow struct {
	LineageID string `json:"lineage_id"`
	Ref       string `json:"ref"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	Title     string `json:"title"`
	RelPath   string `json:"rel_path"`
	LineStart int    `json:"line_start"`
	// Tier is derived from the row's provenance by TierOf — never stored as a
	// second source of truth.
	Tier string `json:"tier"`
	// SeenCount is how many scans found THIS finding; ScanCount is how many
	// scans are in the selected set. Together they are the "seen in 2 of 5
	// scans" bar, and collapsing them into one number is what makes a finding
	// reported once by five scans indistinguishable from five findings.
	SeenCount   int       `json:"seen_count"`
	ScanCount   int       `json:"scan_count"`
	Status      string    `json:"status"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	// LastEvent is the most recent lineage event type: WHY the row is where it
	// is (`confirmed_by_evidence` reads very differently from `fixed`).
	LastEvent string `json:"last_event"`
}

// AggregateTiles is the headline strip above the table.
//
// The tiles describe the TARGET within the selected scans, NOT the filtered
// row set, and that is load-bearing: under the default `status=active` view
// the `fixed` tile is the only thing telling a user that closed findings exist
// and are one click away. A tile that moved with the status filter would read
// 0 in exactly the view where it matters.
type AggregateTiles struct {
	Unique      int `json:"unique"`
	Active      int `json:"active"`
	Unconfirmed int `json:"unconfirmed"`
	Fixed       int `json:"fixed"`
	// Critical counts ACTIVE critical rows: a critical finding that was fixed
	// is history, not a number to act on today.
	Critical int `json:"critical"`
}

// AggregateReport is the whole GET /api/targets/{key}/aggregate payload.
type AggregateReport struct {
	// Total is the size of the FILTERED set BEFORE paging. A total that counts
	// the returned page turns the pager into a lie (page 2 of 1); a total that
	// counts the whole target makes every filter look like it did nothing.
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Tiles    AggregateTiles `json:"tiles"`
	Rows     []AggregateRow `json:"rows"`
}

// LineageEvidence is the block GET /api/lineage/{id} gains (§10.1). Without it
// the detail page can say a row is `open` but not that a scan RE-READ the file
// and found the quote still there — the difference between "nobody mentioned
// it" and "it is still in the code", which is the whole subject of 0091.
type LineageEvidence struct {
	// LastOutcome is the last evidence observation: confirmed, gone,
	// unconfirmable, out_of_scope, skipped_degraded, absent_in_result or
	// scope_unknown.
	LastOutcome string    `json:"last_outcome"`
	Reason      string    `json:"reason"`
	LineStart   int       `json:"line_start"`
	LineEnd     int       `json:"line_end"`
	FileHash    string    `json:"file_hash"`
	CheckedAt   time.Time `json:"checked_at"`
}

// LineageDetail is the GET /api/lineage/{id} payload. `lineage` and `events`
// are the pre-0091 shape and are unchanged: this endpoint is EXTENDED, not
// replaced, and the /audit/{id} deep links already read those two keys.
type LineageDetail struct {
	Lineage  *FindingLineage  `json:"lineage"`
	Events   []LineageEvent   `json:"events"`
	Evidence *LineageEvidence `json:"evidence"`
	// SeenIn is the audits that reported this finding, matched by
	// fingerprint_v2. It is computed HERE and nowhere else: that read touches
	// `findings`, which the aggregate is forbidden to join. One row's worth is
	// cheap and indexed; a whole report's worth is what makes the report
	// unusable.
	SeenIn []string `json:"seen_in"`
}

// EvidenceOutcomes maps the 0091 evidence events onto the short outcome name
// the detail page renders. An event absent from this map is not an evidence
// observation (`detected`, `status_change`, `note_added`, …) and never becomes
// the last outcome.
var EvidenceOutcomes = map[LineageEventType]string{
	LineageEventConfirmedByEvidence: "confirmed",
	LineageEventEvidenceGone:        "gone",
	LineageEventUnconfirmable:       "unconfirmable",
	LineageEventOutOfScope:          "out_of_scope",
	LineageEventSkippedDegraded:     "skipped_degraded",
	LineageEventAbsentInResult:      "absent_in_result",
	LineageEventScopeUnknown:        "scope_unknown",
	LineageEventReported:            "reported",
}
